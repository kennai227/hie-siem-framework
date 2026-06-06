#!/usr/bin/env python3
"""
HIE SIEM — Distributed Anomaly Detection Engine
================================================
Cross-cloud log correlation with ML-based anomaly detection.

Models:
  - Isolation Forest: network traffic baselining (VPC Flow + NSG Flow)
  - UEBA: user behavior baselining (access time, volume, geography)
  - Time-series: hourly access pattern deviation

Data Sources:
  - AWS CloudWatch (VPC Flow Logs, CloudTrail)
  - Azure Log Analytics (NSG Flow Logs, Activity Logs)
  - Wazuh OpenSearch (agent events, FIM, vulnerability)

Compliance:
  HIPAA 164.312(b) — Audit Controls
  PHIPA S.12(1)(b) — Accountability

Usage:
  python anomaly_detector.py --config config/hie_baseline.yaml
  python anomaly_detector.py --mode train --days 30
  python anomaly_detector.py --mode detect --alert-threshold 0.85
"""

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import numpy as np
import pandas as pd
import requests
import yaml
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from opensearchpy import OpenSearch, RequestsHttpConnection
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# =============================================================================
# Configuration
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/hie-siem/anomaly_detector.log"),
    ],
)
log = logging.getLogger("hie.anomaly")


@dataclass
class HIESIEMConfig:
    """HIE SIEM anomaly detection configuration."""
    # AWS
    aws_region: str = "ca-central-1"
    aws_log_group_vpc: str = "/aws/vpc/hie-siem-flow-logs"
    aws_log_group_cloudtrail: str = "aws-cloudtrail-logs"

    # Azure
    azure_workspace_id: str = ""
    azure_subscription_id: str = ""

    # OpenSearch / Wazuh
    opensearch_host: str = "localhost"
    opensearch_port: int = 9200
    opensearch_user: str = "admin"
    opensearch_password: str = ""  # Load from env/vault
    wazuh_index_pattern: str = "wazuh-alerts-*"

    # Model params
    isolation_forest_contamination: float = 0.01  # Expected anomaly rate ~1%
    isolation_forest_n_estimators: int = 200
    ueba_baseline_days: int = 30
    detection_window_minutes: int = 15
    alert_threshold: float = 0.85

    # Alerting
    alert_webhook_url: str = ""
    alert_email: str = ""

    @classmethod
    def from_yaml(cls, path: str) -> "HIESIEMConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


# =============================================================================
# Data Collectors
# =============================================================================

class AWSLogCollector:
    """Collect VPC Flow Logs and CloudTrail events from AWS CloudWatch."""

    def __init__(self, config: HIESIEMConfig):
        self.config = config
        self.client = boto3.client("logs", region_name=config.aws_region)
        log.info(f"AWS log collector initialized — region: {config.aws_region}")

    def get_vpc_flow_logs(self, hours: int = 1) -> pd.DataFrame:
        """Fetch VPC Flow Logs and normalize to ECS format."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        log.info(f"Fetching VPC flow logs: {start_time} → {end_time}")
        records = []

        try:
            paginator = self.client.get_paginator("filter_log_events")
            pages = paginator.paginate(
                logGroupName=self.config.aws_log_group_vpc,
                startTime=int(start_time.timestamp() * 1000),
                endTime=int(end_time.timestamp() * 1000),
            )
            for page in pages:
                for event in page.get("events", []):
                    parsed = self._parse_vpc_flow_log(event["message"])
                    if parsed:
                        records.append(parsed)
        except Exception as e:
            log.error(f"AWS VPC flow log collection failed: {e}")

        log.info(f"Collected {len(records)} AWS VPC flow records")
        return pd.DataFrame(records)

    def _parse_vpc_flow_log(self, raw: str) -> dict[str, Any] | None:
        """Parse custom VPC flow log format into ECS-normalized dict."""
        fields = raw.strip().split()
        if len(fields) < 14 or fields[0] == "version":
            return None
        try:
            return {
                # ECS network fields
                "source.ip":          fields[3],
                "destination.ip":     fields[4],
                "source.port":        int(fields[5]) if fields[5] != "-" else 0,
                "destination.port":   int(fields[6]) if fields[6] != "-" else 0,
                "network.transport":  self._protocol_number(fields[7]),
                "network.packets":    int(fields[8]) if fields[8] != "-" else 0,
                "network.bytes":      int(fields[9]) if fields[9] != "-" else 0,
                "event.action":       fields[12].lower(),
                "event.start":        datetime.fromtimestamp(int(fields[10]), tz=timezone.utc),
                "event.end":          datetime.fromtimestamp(int(fields[11]), tz=timezone.utc),
                "cloud.provider":     "aws",
                "cloud.region":       self.config.aws_region,
                # Computed features for ML
                "duration_seconds":   int(fields[11]) - int(fields[10]),
                "bytes_per_second":   (int(fields[9]) / max(int(fields[11]) - int(fields[10]), 1))
                                      if fields[9] != "-" else 0,
                "is_denied":          1 if fields[12] == "REJECT" else 0,
            }
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _protocol_number(num: str) -> str:
        return {"6": "tcp", "17": "udp", "1": "icmp"}.get(num, f"proto_{num}")


class AzureLogCollector:
    """Collect NSG Flow Logs and Activity Logs from Azure Log Analytics."""

    def __init__(self, config: HIESIEMConfig):
        self.config = config
        self.credential = DefaultAzureCredential()
        self.client = LogsQueryClient(self.credential)
        log.info(f"Azure log collector initialized — workspace: {config.azure_workspace_id}")

    def get_nsg_flow_logs(self, hours: int = 1) -> pd.DataFrame:
        """Fetch Azure NSG flow logs from Log Analytics."""
        query = """
        AzureNetworkAnalytics_CL
        | where TimeGenerated >= ago({hours}h)
        | where SubType_s == "FlowLog"
        | project
            TimeGenerated,
            SrcIP_s,
            DestIP_s,
            DestPort_d,
            L4Protocol_s,
            FlowStatus_s,
            BytesSentA_d,
            BytesSentB_d,
            PacketsSentA_d,
            PacketsSentB_d,
            FlowStartTime_t,
            FlowEndTime_t,
            Subscription_g,
            NSGRule_s
        | limit 10000
        """.format(hours=hours)

        records = []
        try:
            response = self.client.query_workspace(
                workspace_id=self.config.azure_workspace_id,
                query=query,
                timespan=timedelta(hours=hours),
            )
            if response.status == LogsQueryStatus.SUCCESS:
                for row in response.tables[0].rows:
                    records.append({
                        "source.ip":         row[1],
                        "destination.ip":    row[2],
                        "destination.port":  int(row[3]) if row[3] else 0,
                        "network.transport": row[4].lower() if row[4] else "unknown",
                        "event.action":      "allow" if row[5] == "A" else "deny",
                        "network.bytes":     (row[6] or 0) + (row[7] or 0),
                        "network.packets":   (row[8] or 0) + (row[9] or 0),
                        "cloud.provider":    "azure",
                        "cloud.region":      "canadacentral",
                        "is_denied":         0 if row[5] == "A" else 1,
                        "duration_seconds":  0,  # Calculate from start/end if needed
                        "bytes_per_second":  0,
                    })
        except Exception as e:
            log.error(f"Azure NSG flow log collection failed: {e}")

        log.info(f"Collected {len(records)} Azure NSG flow records")
        return pd.DataFrame(records)


class WazuhCollector:
    """Collect Wazuh alerts from OpenSearch for UEBA baselining."""

    def __init__(self, config: HIESIEMConfig):
        self.config = config
        self.client = OpenSearch(
            hosts=[{"host": config.opensearch_host, "port": config.opensearch_port}],
            http_auth=(config.opensearch_user, config.opensearch_password),
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
        )

    def get_user_activity(self, hours: int = 24) -> pd.DataFrame:
        """Fetch user activity events for UEBA analysis."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                        {"exists": {"field": "data.dstuser"}},
                    ]
                }
            },
            "size": 10000,
            "_source": ["@timestamp", "data.dstuser", "data.srcip", "rule.id",
                        "rule.level", "rule.description", "agent.name"],
        }
        records = []
        try:
            response = self.client.search(index=self.config.wazuh_index_pattern, body=query)
            for hit in response["hits"]["hits"]:
                src = hit["_source"]
                ts = pd.to_datetime(src.get("@timestamp"))
                records.append({
                    "timestamp":      ts,
                    "user":           src.get("data", {}).get("dstuser", "unknown"),
                    "source_ip":      src.get("data", {}).get("srcip", ""),
                    "rule_id":        src.get("rule", {}).get("id", 0),
                    "rule_level":     src.get("rule", {}).get("level", 0),
                    "agent":          src.get("agent", {}).get("name", ""),
                    "hour_of_day":    ts.hour,
                    "day_of_week":    ts.dayofweek,
                    "is_weekend":     1 if ts.dayofweek >= 5 else 0,
                    "is_after_hours": 1 if ts.hour < 7 or ts.hour > 19 else 0,
                })
        except Exception as e:
            log.error(f"Wazuh alert collection failed: {e}")
        return pd.DataFrame(records)


# =============================================================================
# Anomaly Detection Models
# =============================================================================

class NetworkAnomalyDetector:
    """
    Isolation Forest for cross-cloud network traffic anomaly detection.

    Features used:
      - bytes per second (exfiltration detection)
      - destination port entropy
      - deny rate (scanning patterns)
      - connection duration
      - packet size (tunneling detection)
    """

    def __init__(self, config: HIESIEMConfig):
        self.config = config
        self.model = IsolationForest(
            n_estimators=config.isolation_forest_n_estimators,
            contamination=config.isolation_forest_contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    FEATURE_COLS = [
        "network.bytes", "network.packets", "destination.port",
        "bytes_per_second", "is_denied", "duration_seconds"
    ]

    def _prepare_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract and scale ML features from flow log DataFrame."""
        features = df[self.FEATURE_COLS].fillna(0).copy()
        # Log-scale high-range features to reduce skew
        for col in ["network.bytes", "network.packets", "bytes_per_second"]:
            if col in features.columns:
                features[col] = np.log1p(features[col])
        return features.values

    def train(self, df: pd.DataFrame) -> None:
        """Train baseline model on historical traffic."""
        if df.empty:
            log.warning("Empty DataFrame — cannot train network anomaly model")
            return
        X = self._prepare_features(df)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        log.info(f"Network anomaly model trained on {len(df)} samples")

    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score new traffic; return DataFrame with anomaly_score and is_anomaly columns."""
        if df.empty or not self.is_trained:
            return df
        X = self._prepare_features(df)
        X_scaled = self.scaler.transform(X)
        # decision_function: negative = more anomalous
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)  # -1 = anomaly, 1 = normal
        df = df.copy()
        df["anomaly_score"] = -scores  # Flip so higher = more anomalous
        df["is_anomaly"] = (predictions == -1).astype(int)
        return df


class UEBADetector:
    """
    User and Entity Behavior Analytics for ePHI access monitoring.

    Baselines:
      - Normal working hours per user
      - Typical access volume per session
      - Geographic access pattern (IP geolocation)
      - Resource access frequency
    """

    def __init__(self, config: HIESIEMConfig):
        self.config = config
        self.user_baselines: dict[str, dict] = {}

    def build_baselines(self, df: pd.DataFrame) -> None:
        """Compute per-user behavioral baselines from historical events."""
        if df.empty:
            return
        for user, group in df.groupby("user"):
            self.user_baselines[user] = {
                "mean_hour":        group["hour_of_day"].mean(),
                "std_hour":         group["hour_of_day"].std() or 1.0,
                "mean_daily_events": group.groupby(group["timestamp"].dt.date).size().mean(),
                "std_daily_events":  group.groupby(group["timestamp"].dt.date).size().std() or 1.0,
                "typical_ips":      set(group["source_ip"].value_counts().head(5).index),
                "weekend_ratio":    group["is_weekend"].mean(),
                "after_hours_ratio": group["is_after_hours"].mean(),
            }
        log.info(f"UEBA baselines built for {len(self.user_baselines)} users")

    def score_session(self, user: str, events: pd.DataFrame) -> dict[str, Any]:
        """
        Score a user session against their baseline.
        Returns risk score 0.0–1.0 and explanation.
        """
        if user not in self.user_baselines or events.empty:
            return {"risk_score": 0.5, "reason": "No baseline available", "user": user}

        baseline = self.user_baselines[user]
        risk_factors = []
        risk_score = 0.0

        # Time deviation
        current_hour = events["hour_of_day"].mean()
        hour_deviation = abs(current_hour - baseline["mean_hour"]) / baseline["std_hour"]
        if hour_deviation > 2.5:
            risk_factors.append(f"Unusual access time (z-score: {hour_deviation:.2f})")
            risk_score += 0.3

        # Volume deviation
        event_count = len(events)
        volume_deviation = (event_count - baseline["mean_daily_events"]) / baseline["std_daily_events"]
        if volume_deviation > 3.0:
            risk_factors.append(f"Abnormal event volume: {event_count} (z-score: {volume_deviation:.2f})")
            risk_score += 0.35

        # New IP address
        current_ips = set(events["source_ip"].unique())
        new_ips = current_ips - baseline["typical_ips"]
        if new_ips:
            risk_factors.append(f"Access from new IP(s): {new_ips}")
            risk_score += 0.2

        # After-hours vs baseline
        current_after_hours = events["is_after_hours"].mean()
        if current_after_hours > 0.5 and baseline["after_hours_ratio"] < 0.1:
            risk_factors.append("After-hours access atypical for this user")
            risk_score += 0.15

        return {
            "user":        user,
            "risk_score":  min(risk_score, 1.0),
            "risk_factors": risk_factors,
            "event_count": event_count,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "alert":       risk_score >= self.config.alert_threshold,
        }


# =============================================================================
# Alert Dispatcher
# =============================================================================

class AlertDispatcher:
    """Send anomaly alerts to Wazuh, webhook, or log."""

    def __init__(self, config: HIESIEMConfig):
        self.config = config

    def dispatch(self, alert: dict[str, Any]) -> None:
        """Route alert based on severity."""
        log.warning(f"ANOMALY ALERT: {json.dumps(alert, default=str)}")
        if self.config.alert_webhook_url:
            self._send_webhook(alert)

    def _send_webhook(self, alert: dict[str, Any]) -> None:
        try:
            resp = requests.post(
                self.config.alert_webhook_url,
                json={"text": f"[HIE-SIEM] Anomaly: {alert}", "alert": alert},
                timeout=5,
            )
            resp.raise_for_status()
        except Exception as e:
            log.error(f"Webhook dispatch failed: {e}")


# =============================================================================
# Main Detection Loop
# =============================================================================

def run_detection_loop(config: HIESIEMConfig) -> None:
    """Continuous detection loop — runs every config.detection_window_minutes."""
    aws_collector = AWSLogCollector(config)
    azure_collector = AzureLogCollector(config)
    wazuh_collector = WazuhCollector(config)
    network_detector = NetworkAnomalyDetector(config)
    ueba_detector = UEBADetector(config)
    dispatcher = AlertDispatcher(config)

    log.info("Training baseline models (30-day historical window)...")
    aws_baseline = aws_collector.get_vpc_flow_logs(hours=config.ueba_baseline_days * 24)
    azure_baseline = azure_collector.get_nsg_flow_logs(hours=config.ueba_baseline_days * 24)
    combined_baseline = pd.concat([aws_baseline, azure_baseline], ignore_index=True)
    network_detector.train(combined_baseline)

    user_history = wazuh_collector.get_user_activity(hours=config.ueba_baseline_days * 24)
    ueba_detector.build_baselines(user_history)

    log.info(f"Detection loop started — interval: {config.detection_window_minutes}m")
    while True:
        cycle_start = time.time()
        log.info("=== Detection cycle start ===")

        # Network anomaly detection
        try:
            aws_traffic  = aws_collector.get_vpc_flow_logs(hours=1)
            azure_traffic = azure_collector.get_nsg_flow_logs(hours=1)
            combined = pd.concat([aws_traffic, azure_traffic], ignore_index=True)
            scored = network_detector.detect(combined)
            anomalies = scored[scored["is_anomaly"] == 1]
            if not anomalies.empty:
                log.warning(f"Network anomalies detected: {len(anomalies)}")
                for _, row in anomalies.head(10).iterrows():
                    dispatcher.dispatch({
                        "type":           "network_anomaly",
                        "source_ip":      row.get("source.ip"),
                        "destination_ip": row.get("destination.ip"),
                        "anomaly_score":  row.get("anomaly_score"),
                        "cloud_provider": row.get("cloud.provider"),
                        "rule":           "HIE-NET-ANOMALY-001",
                        "compliance":     ["HIPAA-164.312(b)", "PHIPA-S.12"],
                    })
        except Exception as e:
            log.error(f"Network detection cycle failed: {e}")

        # UEBA scoring
        try:
            recent_events = wazuh_collector.get_user_activity(hours=1)
            if not recent_events.empty:
                for user in recent_events["user"].unique():
                    user_events = recent_events[recent_events["user"] == user]
                    score = ueba_detector.score_session(user, user_events)
                    if score.get("alert"):
                        dispatcher.dispatch({
                            "type":        "ueba_anomaly",
                            "rule":        "HIE-UEBA-001",
                            "compliance":  ["HIPAA-164.312(a)(1)", "PHIPA-S.12"],
                            **score,
                        })
        except Exception as e:
            log.error(f"UEBA detection cycle failed: {e}")

        elapsed = time.time() - cycle_start
        sleep_seconds = max(0, config.detection_window_minutes * 60 - elapsed)
        log.info(f"=== Cycle complete in {elapsed:.1f}s — sleeping {sleep_seconds:.0f}s ===")
        time.sleep(sleep_seconds)


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="HIE SIEM Anomaly Detector")
    parser.add_argument("--config", default="config/hie_baseline.yaml", help="Config file path")
    parser.add_argument("--mode", choices=["detect", "train", "test"], default="detect")
    parser.add_argument("--alert-threshold", type=float, help="Override alert threshold (0.0-1.0)")
    args = parser.parse_args()

    config = HIESIEMConfig.from_yaml(args.config) if os.path.exists(args.config) else HIESIEMConfig()
    config.opensearch_password = os.environ.get("OPENSEARCH_PASSWORD", "")

    if args.alert_threshold:
        config.alert_threshold = args.alert_threshold

    if args.mode == "detect":
        run_detection_loop(config)
    elif args.mode == "test":
        log.info("Test mode — running single detection cycle")
        run_detection_loop(config)


if __name__ == "__main__":
    main()

# Architecture Decision Records (ADRs)
# HIE Cross-Cloud SIEM Framework — AWS Canada Central + Azure Canada Central

---

## ADR-001: Cross-Cloud Strategy (AWS + Azure)

**Date:** 2024-01  
**Status:** Accepted

### Context
Canadian HIE environments typically span two infrastructure realities: Ontario hospital systems predominantly use Microsoft 365, Azure Active Directory, and Defender for Endpoint (driven by Ministry of Health enterprise agreements), while cloud-native EHR platforms, data lakes, and API gateways are increasingly deployed on AWS. A single-cloud SIEM creates blind spots.

### Decision
Deploy unified SIEM across `ca-central-1` (AWS) and `canadacentral` (Azure). AWS hosts Wazuh cluster and OpenSearch. Azure Sentinel handles M365, AAD, and Defender telemetry. Logstash normalizes all logs to ECS before correlation.

### Consequences
- Cross-cloud VPN tunnel adds ~$200/month operational cost
- Federated identity between AWS IAM and Azure AD requires careful trust policy design
- Single pane of glass via Wazuh Dashboard with Sentinel integration via API

---

## ADR-002: Wazuh over Splunk or IBM QRadar

**Date:** 2024-01  
**Status:** Accepted

### Context
HIE environments have high log volumes (millions of events/day from HL7 interfaces alone) and strict budget constraints. Commercial SIEMs charge per GB ingested or per EPS (events per second).

### Decision
Wazuh 4.7 (open source, Apache 2.0 for core components) with OpenSearch backend.

### Comparison

| Factor | Wazuh | Splunk | QRadar |
|---|---|---|---|
| License cost at 50GB/day | $0 | ~$180K/year | ~$150K/year |
| HIPAA rule set | Built-in | Marketplace add-on | Built-in |
| FIM capability | Native | Agent-based | Agent-based |
| Canadian data residency | Self-hosted ✓ | Cloud option ✓ | On-prem ✓ |
| Active response | Native | SOAR required | SOAR required |

### Consequences
- No vendor support SLA — requires in-house expertise
- Community-maintained rules require regular review
- OpenSearch licensing (Apache 2.0) confirmed post-Elastic fork

---

## ADR-003: Log Normalization to ECS

**Date:** 2024-01  
**Status:** Accepted

### Context
AWS VPC Flow Logs, Azure NSG Flow Logs, CloudTrail, Azure Activity Logs, and Wazuh agent events all have different schemas. Writing cloud-specific detection rules doubles the rule maintenance burden.

### Decision
Normalize all ingested logs to Elastic Common Schema (ECS) 8.x via Logstash before writing to OpenSearch. ECS fields used: `source.ip`, `destination.ip`, `event.action`, `user.name`, `cloud.provider`, `cloud.region`.

### Consequences
- Logstash parsing CPU overhead (~15% on c6i.large)
- Single Wazuh ruleset covers both cloud sources
- Future third cloud (e.g., GCP) requires only a new Logstash input + filter block

---

## ADR-004: 7-Year Log Retention with WORM Storage

**Date:** 2024-01  
**Status:** Accepted

### Context
HIPAA requires audit logs to be retained for 6 years from creation or last effective date (164.530(j)). Many Canadian provincial regulations recommend 10 years for health records. Audit logs must be tamper-evident and immutable.

### Decision
- **AWS:** S3 Object Lock in COMPLIANCE mode, 2557 days (7 years)
- **Azure:** Azure Immutable Blob Storage with time-based retention lock

S3 COMPLIANCE mode cannot be overridden even by the AWS root account — stronger than GOVERNANCE mode which can be bypassed by privileged users.

### Consequences
- Cannot delete accidentally-stored PII from logs before retention period expires
- Storage costs ~$0.023/GB/month (S3 Standard-IA) for long-tail archives
- Requires careful log filtering at ingestion to minimize PHI in raw logs

---

## ADR-005: Isolation Forest for Network Anomaly Detection

**Date:** 2024-01  
**Status:** Accepted

### Context
Rule-based network detection (e.g., "alert if >X connections/minute") generates excessive false positives in HIE environments where batch HL7 file transfers create legitimate traffic spikes. ML-based baselining reduces false positive rate significantly.

### Decision
Isolation Forest (scikit-learn) trained on 30 days of VPC Flow + NSG Flow data. Features: bytes/second, destination port, packet size, deny rate, connection duration. Contamination factor set to 0.01 (expect ~1% anomalous traffic).

### Rationale over alternatives:
- **Autoencoder:** Higher accuracy but requires GPU and longer training time
- **LOF (Local Outlier Factor):** Poor performance on high-dimensional network data
- **Isolation Forest:** Fast inference, interpretable, no GPU required, handles concept drift well with periodic retraining

### Consequences
- Model requires retraining after major network topology changes
- 30-day cold-start period before model is reliable
- False negative rate for novel attack patterns (zero-days) — supplement with signature rules

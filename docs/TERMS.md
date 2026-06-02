# Terms of Service

**Data Governance Pipeline** — Last updated: June 2, 2026

## 1. Acceptance

By using the Data Governance Pipeline, you agree to these terms. If you do not agree, do not use the software.

## 2. License

The Data Governance Pipeline is distributed under the MIT License. You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, subject to the conditions in the LICENSE file.

## 3. Description of Service

The Data Governance Pipeline is a production-grade Python ETL tool with built-in GDPR, CCPA, and HIPAA compliance. It extracts data from configured sources, applies governance transformations, and loads data to configured destinations.

## 4. Your Responsibilities

### As a Data Controller

You are the data controller for all data processed by the pipeline. You are responsible for:

- **Lawful basis** — Ensuring you have a lawful basis (consent, legitimate interest, contract, etc.) for processing the data you ingest
- **Data subject rights** — Responding to access, deletion, correction, and portability requests from data subjects
- **Vendor agreements** — Establishing appropriate Data Processing Agreements (DPAs) and Business Associate Agreements (BAAs) with destination services
- **Access control** — Securing the pipeline, its configuration, and credential files
- **Compliance** — Ensuring your pipeline configuration complies with GDPR, CCPA, HIPAA, and other applicable regulations

### As an Operator

You are responsible for:

- **Configuration accuracy** — Data contracts, schema definitions, PII classification rules, and consent configurations
- **Credential security** — Protecting `.env` files, API keys, and database credentials
- **Destination authorization** — Ensuring you have permission to write data to configured destinations
- **Monitoring** — Reviewing audit logs, compliance reports, and anomaly alerts
- **Retention** — Configuring and enforcing appropriate data retention policies

## 5. Compliance Tools, Not Compliance Guarantees

The pipeline provides tools to assist with regulatory compliance:

| Tool | What it does | What it does NOT do |
|------|-------------|-------------------|
| PII Discovery | Detects common PII patterns | Does not guarantee all PII is found |
| HIPAA Safe Harbor | Removes 18 identifier categories | Does not certify HIPAA compliance |
| GDPR Controls | Supports consent, erasure, portability | Does not replace a DPO or legal review |
| CCPA Controls | Supports opt-out, deletion, disclosure | Does not replace legal counsel |
| Audit Ledger | Records operations with tamper evidence | Does not satisfy all regulatory audit requirements |
| k-Anonymity | Enforces k=5 with l-diversity | Does not prevent all re-identification |

**These tools assist your compliance program. They do not replace legal counsel, a Data Protection Officer, or regulatory certification.**

## 6. No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

Specifically:
- The pipeline may fail to detect all PII in your data
- De-identification may be incomplete or reversible under certain conditions
- Data transformations may produce incorrect results
- Destination loads may fail, leaving partial data
- Compliance tools may not satisfy all regulatory requirements in your jurisdiction
- The audit ledger may not meet all evidentiary standards

**Do not rely solely on this software for regulatory compliance.**

## 7. Limitation of Liability

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This includes but is not limited to:
- Regulatory fines or penalties
- Data breaches or unauthorized access
- Data loss or corruption during ETL operations
- Incorrect de-identification or pseudonymization
- Failed compliance audits
- Costs of incident response or notification

## 8. Healthcare Data (HIPAA)

If you process Protected Health Information (PHI):

- You must have a BAA with every destination that receives PHI
- The pipeline's HIPAA Safe Harbor filter assists with de-identification but does not certify compliance
- You must designate a HIPAA Privacy Officer
- The pipeline's BAA tracker is a management tool, not a legal instrument
- Epic EHR integration requires separate authorization from the healthcare organization

## 9. Third-Party Services

Data sent to configured destinations is governed by those services' terms:

- **Cloud providers** — AWS, GCP, Azure terms and DPAs apply
- **SaaS platforms** — Snowflake, Databricks, etc. terms apply
- **Healthcare systems** — Epic, OMOP terms and BAAs apply
- **Monitoring** — Grafana, Prometheus terms apply

You are responsible for reviewing and accepting those terms.

## 10. Acceptable Use

Do not use the Data Governance Pipeline to:
- Process data without lawful basis or authorization
- Circumvent data protection regulations
- Re-identify de-identified data in violation of regulations
- Exfiltrate data from systems without authorization
- Bypass access controls or security measures

## 11. Modifications

These terms may be updated in future releases. Changes will be documented in the repository's commit history.

## 12. Governing Law

These terms are governed by the laws of the State of New York, United States.

## Contact

For questions, open an issue at: https://github.com/MatthewRyanWeber/data-governance-pipeline/issues

Or contact: matt@nyss.nyc

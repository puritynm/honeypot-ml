\🍯Honeypot ML Detection System



A multi-layer honeypot that uses supervised machine learning to classify attack traffic and reduce false positives by \~30% compared to rule-based detection.



\Live Dashboard

👉 \[View SOC Dashboard]( https://puritynm.github.io/honeypot-ml/dashboard.html )



\ Features

\- Multi-layer honeypot sensors (SSH, HTTP, FTP, SMB, DNS)

\- Supervised ML classifiers (Random Forest, Gradient Boosting)

\- \~30% false positive reduction vs rule-based baseline

\- MITRE ATT\&CK TTP tagging

\- Real-time SOC alert prioritization

\- Campaign clustering and deduplication



\ Quick Start

```bash

pip install -r requirements.txt

python main.py

```



\ Project Structure

\- `src/honeypot/` — telemetry collection

\- `src/pipeline/` — feature engineering

\- `src/ml/` — model training and evaluation

\- `src/alerts/` — alert prioritization engine

\- `docs/` — SOC dashboard and architecture docs


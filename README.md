# 🛡️ AI Cyber Attack Detection & Monitoring System

Real-time AI-powered cybersecurity SOC dashboard with **deployable monitoring agent** for external websites.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Flask](https://img.shields.io/badge/Flask-3.x-black) ![ML](https://img.shields.io/badge/ML-RandomForest-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🚀 Features

- **AI Threat Detection** — Random Forest model trained on NSL-KDD dataset (25+ attack types)
- **Real-time SOC Dashboard** — Live attack feed, charts, packet stream, terminal logs
- **Deployable Agent** — Embed 2-line `<script>` on any website for instant monitoring
- **Multi-site Monitor** — Track multiple websites from one dashboard
- **Auto IP Blocking** — Critical = permanent block, High = 24h temporary
- **Per-site Data Isolation** — Each site can only access its own logs via API key

---

## 📋 Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/YOUR_USERNAME/cyber-attack-detection.git
cd cyber-attack-detection
pip install -r requirements.txt
```

### 2. Train the Model *(one-time, ~2 min)*
> Download `KDDTrain+.txt` from [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html) and place it in the project root.
```bash
python train_model.py
```
This generates `attack_model.pkl`, `encoders.pkl`, `columns.pkl`.

### 3. Run the Server
```bash
# Optional: set admin key (default: soc-admin-secret-change-me)
set SOC_ADMIN_KEY=your-strong-secret     # Windows
export SOC_ADMIN_KEY=your-strong-secret  # Linux/Mac

python app.py
```
Open **http://127.0.0.1:5000**

---

## 🌐 Deploy Agent on Any Website

1. Go to **Deploy Agent** tab on the dashboard
2. Copy your site's `site_id` and `api_key`
3. Paste into your website's `<head>`:

```html
<script src="https://YOUR-SOC-SERVER/static/agent.js"
        data-site="your-site-id"
        data-key="your-api-key"></script>
```

4. Open **Site Monitor** tab → select your site → real-time monitoring starts

---

## 🔐 Security Model

| Endpoint | Access |
|----------|--------|
| `GET /api/sites` | Public — no API keys exposed |
| `POST /api/agent/report` | Requires valid `site_id + api_key` |
| `GET /api/agent/logs` | Requires matching `api_key` (site sees own data only) |
| `GET /api/admin/sites` | Requires `X-Admin-Key` header |

---

## 🗂️ Project Structure

```
.
├── app.py              # Flask server + all API endpoints
├── database.py         # SQLite persistence layer
├── train_model.py      # Model training script (NSL-KDD)
├── utils.py            # Severity / response helpers
├── simulate.py         # Attack simulation script
├── requirements.txt
└── static/
    ├── index.html      # SOC Dashboard UI
    ├── embed.html      # Deploy Agent instructions
    ├── agent.js        # Embeddable monitoring snippet
    ├── script.js       # Dashboard logic
    └── styles.css      # Dark cyberpunk theme
```

---

## ⚙️ Requirements

```
Flask
pandas
scikit-learn
```

---

## 📄 License

MIT — free to use, modify, and deploy.

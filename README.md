# JobGuard — Fake Job / Internship Detection System

> College project · Flask + Scikit-learn + HTML/CSS3/JS

JobGuard is a web application that analyses job postings and internship listings to detect whether they are potentially fake or fraudulent. It combines **rule-based pattern matching** with a **Machine Learning classifier** to produce a final risk score between 0–100.

---

## Project Structure

```
fake-job-detector/
│
├── app.py                        ← Flask application (all routes)
│
├── model/
│   ├── train_model.py            ← TF-IDF + Logistic Regression trainer
│   ├── fake_job_model.pkl        ← Trained model (generated)
│   └── vectorizer.pkl            ← TF-IDF vectorizer (generated)
│
├── templates/
│   ├── base.html                 ← Shared Jinja2 layout
│   ├── index.html                ← Main analysis page
│   ├── result.html               ← Shareable result page
│   ├── admin.html                ← Admin dashboard
│   └── 404.html                  ← Error page
│
├── static/
│   ├── css/style.css             ← All styles (dark theme)
│   └── js/app.js                 ← Detection engine + Flask API calls
│
├── database/
│   └── jobs.db                   ← SQLite database (auto-created)
│
├── dataset/
│   ├── fake_job_postings.csv     ← Training dataset (110 labelled rows)
│   └── generate_dataset.py       ← Script to regenerate the CSV
│
├── requirements.txt
└── README.md
```

---

## Setup & Run

### 1. Clone the repository

```bash
git clone <repo-url>
cd fake-job-detector
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

**Dependencies installed (`requirements.txt`):**

| Package | Version | Purpose |
|---|---|---|
| flask | 3.0.3 | Web server & routing |
| scikit-learn | 1.4.2 | ML model (TF-IDF + Logistic Regression) |
| pandas | 2.2.2 | Dataset loading & processing |
| numpy | 1.26.4 | Numerical operations |
| joblib | 1.4.2 | Model serialisation (`.pkl` files) |

### 4. Train the ML model

```bash
python3 model/train_model.py
```

This reads `dataset/fake_job_postings.csv`, trains a TF-IDF + Logistic Regression model, and saves:
- `model/fake_job_model.pkl`
- `model/vectorizer.pkl`

> **Optional upgrade:** Replace `dataset/fake_job_postings.csv` with the real EMSCAD dataset from Kaggle  
> (https://www.kaggle.com/datasets/shivamb/real-or-fake-fake-jobposting-prediction)  
> for significantly higher real-world accuracy (~98%).

### 5. Run the Flask server

```bash
python3 app.py
```

Open your browser at **http://127.0.0.1:5000**

### 6. Stop the server

Press `Ctrl + C` in the terminal where the server is running, or from another terminal:

```bash
pkill -f "python3 app.py"
```

---

## Features

| Feature | Description |
|---|---|
| 🤖 ML Classifier | TF-IDF + Logistic Regression predicts fake/real with confidence % |
| 🔍 Rule-based Engine | 60+ regex patterns across 6 red-flag categories |
| 📧 Email Check | Flags personal domains (Gmail, Yahoo, etc.) |
| 💰 Salary Analysis | Detects unrealistic or below-minimum-wage salaries |
| 🔗 URL Validation | Flags shortened/suspicious links |
| 🏢 Company Check | Flags anonymous or suspicious company names |
| 📊 Score Ring | Animated SVG risk score 0–100 with colour coding |
| ✅ Positive Signals | PF/ESIC, CIN, offer letters, Glassdoor links reduce score |
| 💡 Safety Tips | Context-aware tips based on detected flags |
| 🎯 Demo Presets | One-click fill with Fake / Suspicious / Legit examples |
| 🔗 Shareable Links | `/result/<id>` — server-rendered result page for each scan |
| 🕑 Scan History | localStorage-based last-5-scans on the home page |
| 🛠 Admin Panel | `/admin` — all scans with stats cards and delete action |
| ⬇ Download Report | Export results as a `.txt` file |
| 📋 Copy Summary | Copy result to clipboard |

---

## API Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/` | Main analysis page |
| POST | `/api/analyze` | ML prediction → JSON `{label, confidence, fake_prob}` |
| POST | `/api/save` | Save full scan to DB → JSON `{scan_id}` |
| GET | `/result/<id>` | Shareable result page |
| GET | `/admin` | Admin dashboard |
| POST | `/admin/delete/<id>` | Delete a scan record |

---

## How the Score Works

```
Final Score = 0.6 × Rule-based Score + 0.4 × ML Fake Probability × 100

0–25   → ✅ Likely Safe
26–55  → ⚠️ Suspicious
56–100 → 🚨 High Risk / Likely Fake
```

---

## Tech Stack

- **Backend:** Python 3, Flask
- **ML:** Scikit-learn (TF-IDF + Logistic Regression)
- **Database:** SQLite3 (via Python `sqlite3`)
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Fonts:** Syne, DM Sans (Google Fonts)
- **No frontend framework** — pure vanilla JS for zero dependencies

---

*Built for educational purposes as a college project.*
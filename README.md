# Project Shield — AI-Powered Security Dashboard

**Project Shield** is an AI/ML-powered cybersecurity analytics platform developed as part of the CFSS Global Internship 2026. The system ingests network logs, detects malicious activities via Machine Learning (Isolation Forest and Random Forest), and presents a real-time, interactive threat analysis dashboard.

## Features
- **AI Threat Scoring Engine:** Built with Scikit-learn (Random Forest for classification, Isolation Forest for anomaly detection).
- **Responsive Dashboard:** A modern, glassmorphic UI using vanilla HTML/CSS/JS and Chart.js.
- **Dynamic Threat Intel Reports:** Generates professional, downloadable PDF reports summarizing threat metrics.
- **JWT Authentication:** Secure user authentication with `Flask-JWT-Extended`.
- **Synthetic Data Generation:** Includes a built-in script to generate realistic network attack logs (inspired by NSL-KDD).

---

## 🚀 Quick Setup & Installation

### Prerequisites
- Python 3.12+
- Git

### 1. Clone the repository
```bash
git clone https://github.com/your-username/project-shield.git
cd project-shield
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate Data and Train Models
The project requires a trained model and synthetic logs to function in full AI mode:
```bash
cd backend
python generate_data.py
python train_model.py
```
*(If the models are not generated, the system will seamlessly fallback to rule-based logic).*

### 4. Run the API Server
```bash
python app.py
```

### 5. Access the Dashboard
Open your browser and navigate to:
**http://localhost:5000/**

**Default Login Credentials:**
- Admin: `admin` / `Shield@2026`
- Analyst: `analyst` / `Cfss@2026`

---

## ☁️ Deployment Instructions

The application is configured to be deployed easily on platforms like Render or Heroku. It relies on `gunicorn` for production serving.

1. Create a new Web Service on Render / Heroku.
2. Connect your GitHub repository.
3. Use the following build/start settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --chdir backend app:app`
4. Deploy! The Flask app handles static file serving for the frontend automatically.

---

## 📂 Project Structure

```
.
├── backend/
│   ├── app.py                  # Core Flask REST API and Frontend server
│   ├── generate_data.py        # Log data synthesizer
│   ├── train_model.py          # ML pipeline
│   └── model/                  # Trained model artifacts (.pkl)
├── frontend/
│   ├── index.html              # Login screen
│   ├── dashboard.html          # Main SPA dashboard
│   ├── css/style.css           # Global design system
│   └── js/
│       ├── api.js              # API client and fetching
│       ├── auth.js             # Authentication manager
│       └── dashboard.js        # Core UI controller
├── Procfile                    # Deployment configuration
└── requirements.txt            # Python dependencies
```

## Disclaimer
This software is developed strictly for educational and simulation purposes for the CFSS Global Internship 2026. Data and logs are synthetically generated.

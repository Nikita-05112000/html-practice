# SME Cyber Safety (Prototype)

Lightweight Flask web app for SMEs to detect phishing, train employees, and monitor basic security health.

## Features
- Phishing detection: paste email text or URL and get a risk assessment
- Training module: short quiz; scores ≥ 67% count as completed
- Dashboard: shows risky emails detected, URLs scanned, trainings completed, and alerts

## Tech
- Python 3.10+
- Flask

## Quick Start

1. Create a virtual environment and install deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the app:

```bash
python app.py
```

The app will start on http://localhost:8000

## Notes
- State is stored in `data/state.json` (auto-created). Delete to reset.
- This is a prototype with simple heuristics and simulated data.

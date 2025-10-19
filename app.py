from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
from services.detector import analyze_input
from services.store import Store

app = Flask(__name__)
store = Store(os.path.join('data', 'state.json'))


def get_stats():
    state = store.read_state()
    return state.get('stats', {
        'risky_emails_detected': 0,
        'urls_scanned': 0,
        'trainings_completed': 0,
        'alerts': []
    })


@app.route('/')
def index():
    stats = get_stats()
    return render_template('index.html', stats=stats)


@app.route('/detect', methods=['GET', 'POST'])
def detect():
    result = None
    score = None
    indicators = []
    input_text = ''

    if request.method == 'POST':
        input_text = request.form.get('input_text', '')
        mode = request.form.get('mode', 'auto')
        result, score, indicators = analyze_input(input_text, mode)

        # update stats
        state = store.read_state()
        stats = state.setdefault('stats', {})
        stats['urls_scanned'] = stats.get('urls_scanned', 0) + 1
        if result == 'phishing':
            stats['risky_emails_detected'] = stats.get('risky_emails_detected', 0) + 1
            alerts = stats.setdefault('alerts', [])
            alerts.append({'type': 'phishing', 'message': 'Suspicious input detected', 'score': score})
        store.write_state(state)

    return render_template('detect.html', result=result, score=score, indicators=indicators, input_text=input_text)


QUIZ = [
    {
        'id': 1,
        'q': 'You receive an email saying your account will be closed unless you click a link to verify your password. What should you do?',
        'options': [
            'Click the link and verify immediately',
            'Ignore the email and delete it',
            'Hover over the link, verify sender, and go directly to the official site',
            'Forward to coworkers to ask if it is safe'
        ],
        'answer_idx': 2
    },
    {
        'id': 2,
        'q': 'Which password is strongest?',
        'options': [
            'Summer2024!',
            'P@ssw0rd123',
            'Tr0ub4dor&3',
            'CorrectHorseBatteryStaple!94'
        ],
        'answer_idx': 3
    },
    {
        'id': 3,
        'q': 'MFA (Multi-Factor Authentication) is important because:',
        'options': [
            'It makes logging in faster',
            'It adds an extra layer so stolen passwords aren\'t enough',
            'It replaces the need for passwords',
            'It prevents all cyber attacks'
        ],
        'answer_idx': 1
    }
]


@app.route('/training', methods=['GET', 'POST'])
def training():
    score = None
    total = len(QUIZ)
    selected = {}
    correct_count = 0

    if request.method == 'POST':
        for q in QUIZ:
            selected_idx = request.form.get(f'q_{q["id"]}')
            if selected_idx is not None:
                selected[q['id']] = int(selected_idx)
        correct_count = sum(1 for q in QUIZ if selected.get(q['id']) == q['answer_idx'])
        score = int(round((correct_count / total) * 100))

        # update stats
        state = store.read_state()
        stats = state.setdefault('stats', {})
        # count as completed if >= 67% correct
        if score >= 67:
            stats['trainings_completed'] = stats.get('trainings_completed', 0) + 1
        store.write_state(state)

    return render_template('training.html', quiz=QUIZ, selected=selected, score=score, total=total, correct_count=correct_count)


@app.route('/dashboard')
def dashboard():
    stats = get_stats()
    return render_template('dashboard.html', stats=stats)


@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())


if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    app.run(host='0.0.0.0', port=8000, debug=True)

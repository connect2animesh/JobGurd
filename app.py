"""
JobGuard — Flask Application
==============================
Routes:
  GET  /                → Main analysis page
  POST /api/analyze     → ML prediction (returns JSON)
  POST /api/save        → Persist a full scan to SQLite (returns scan_id)
  GET  /result/<id>     → Shareable server-rendered result page
  GET  /admin           → Admin dashboard (all scans + stats)
  POST /admin/delete/<id> → Delete a scan record
"""

import os
import json
import sqlite3
from datetime import datetime

import joblib
from flask import (Flask, render_template, request,
                   jsonify, redirect, url_for, abort)

# ── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DB_PATH         = os.path.join(BASE_DIR, 'database', 'jobs.db')
MODEL_PATH      = os.path.join(BASE_DIR, 'model', 'fake_job_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'model', 'vectorizer.pkl')

# ── Load ML model ────────────────────────────────────────────────────────────

model      = None
vectorizer = None

if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
    try:
        model      = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        print("[OK] ML model and vectorizer loaded.")
    except Exception as e:
        print(f"[WARN] Could not load model: {e}")
else:
    print("[WARN] Model files not found — ML prediction disabled. Run model/train_model.py first.")

# ── Database ─────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                title        TEXT,
                company      TEXT,
                email        TEXT,
                salary       TEXT,
                url          TEXT,
                description  TEXT,
                risk_score   INTEGER,
                verdict      TEXT,
                verdict_text TEXT,
                ml_label     TEXT,
                ml_confidence REAL,
                flag_count   INTEGER,
                signal_count INTEGER,
                flags        TEXT,
                signals      TEXT,
                breakdown    TEXT,
                created_at   TEXT
            )
        ''')
        conn.commit()

# ── ML prediction helper ──────────────────────────────────────────────────────

def ml_predict(title, company_profile, description, requirements='', benefits=''):
    """Return (label, probability_of_fake) or None if model unavailable."""
    if model is None or vectorizer is None:
        return None
    combined = ' '.join([title, company_profile, description, requirements, benefits])
    vec      = vectorizer.transform([combined])
    proba    = model.predict_proba(vec)[0]
    label    = model.predict(vec)[0]
    return {
        'label':      'Fake' if label == 1 else 'Real',
        'confidence': round(float(proba[label]) * 100, 1),
        'fake_prob':  round(float(proba[1]) * 100, 1),
    }

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', ml_available=(model is not None))


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Return ML prediction as JSON — called from the frontend via fetch()."""
    data         = request.get_json(silent=True) or {}
    title        = data.get('title', '')
    company      = data.get('company', '')
    description  = data.get('desc', '')
    requirements = data.get('requirements', '')
    benefits     = data.get('benefits', '')

    result = ml_predict(title, company, description, requirements, benefits)
    if result is None:
        return jsonify({'ml_available': False})

    return jsonify({'ml_available': True, **result})


@app.route('/api/save', methods=['POST'])
def api_save():
    """Persist a full analysis result and return its scan_id."""
    data = request.get_json(silent=True) or {}

    row = (
        data.get('title', ''),
        data.get('company', ''),
        data.get('email', ''),
        data.get('salary', ''),
        data.get('url', ''),
        data.get('desc', ''),
        int(data.get('risk_score', 0)),
        data.get('verdict', ''),
        data.get('verdict_text', ''),
        data.get('ml_label', ''),
        float(data.get('ml_confidence', 0)),
        int(data.get('flag_count', 0)),
        int(data.get('signal_count', 0)),
        json.dumps(data.get('flags', [])),
        json.dumps(data.get('signals', [])),
        json.dumps(data.get('breakdown', [])),
        datetime.now().strftime('%d %b %Y, %I:%M %p'),
    )

    with get_db() as conn:
        cur = conn.execute('''
            INSERT INTO scans
              (title, company, email, salary, url, description,
               risk_score, verdict, verdict_text, ml_label, ml_confidence,
               flag_count, signal_count, flags, signals, breakdown, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', row)
        conn.commit()
        scan_id = cur.lastrowid

    return jsonify({'scan_id': scan_id})


@app.route('/result/<int:scan_id>')
def result(scan_id):
    """Server-rendered result page — shareable link."""
    with get_db() as conn:
        row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if row is None:
        abort(404)

    scan = dict(row)
    scan['flags']     = json.loads(scan['flags']     or '[]')
    scan['signals']   = json.loads(scan['signals']   or '[]')
    scan['breakdown'] = json.loads(scan['breakdown'] or '[]')
    return render_template('result.html', scan=scan)


@app.route('/admin')
def admin():
    """Admin dashboard — all scans with stats."""
    with get_db() as conn:
        rows = conn.execute(
            'SELECT * FROM scans ORDER BY id DESC'
        ).fetchall()
        stats = conn.execute('''
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN verdict = "danger"     THEN 1 ELSE 0 END) AS fake_count,
                SUM(CASE WHEN verdict = "suspicious" THEN 1 ELSE 0 END) AS suspicious_count,
                SUM(CASE WHEN verdict = "safe"       THEN 1 ELSE 0 END) AS safe_count,
                ROUND(AVG(risk_score), 1)                                AS avg_score
            FROM scans
        ''').fetchone()

    scans = [dict(r) for r in rows]
    return render_template('admin.html', scans=scans, stats=dict(stats))


@app.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    """Return a single scan as JSON — used by the admin drawer."""
    with get_db() as conn:
        row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if row is None:
        return jsonify({'error': 'not found'}), 404
    scan = dict(row)
    scan['flags']     = json.loads(scan['flags']     or '[]')
    scan['signals']   = json.loads(scan['signals']   or '[]')
    scan['breakdown'] = json.loads(scan['breakdown'] or '[]')
    return jsonify(scan)


@app.route('/admin/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    with get_db() as conn:
        conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
    return redirect(url_for('admin'))


# ── 404 handler ───────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print("[OK] Database initialised.")
    print("[OK] Starting JobGuard server on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)

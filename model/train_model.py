"""
JobGuard — ML Model Trainer
============================
Trains a TF-IDF + Logistic Regression classifier on fake_job_postings.csv.
Saves:
  - model/fake_job_model.pkl
  - model/vectorizer.pkl

Usage:
    python model/train_model.py

Replace dataset/fake_job_postings.csv with the real EMSCAD dataset from Kaggle
for higher accuracy: https://www.kaggle.com/datasets/shivamb/real-or-fake-fake-jobposting-prediction
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# ── Paths ──────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'fake_job_postings.csv')
MODEL_PATH   = os.path.join(BASE_DIR, 'model', 'fake_job_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'model', 'vectorizer.pkl')

# ── Load Dataset ───────────────────────────────────────────────────────────

def load_data():
    if not os.path.exists(DATASET_PATH):
        print(f"[ERROR] Dataset not found at: {DATASET_PATH}")
        sys.exit(1)

    df = pd.read_csv(DATASET_PATH)
    print(f"[INFO] Loaded {len(df)} records from dataset.")
    print(f"[INFO] Columns: {list(df.columns)}")
    print(f"[INFO] Label distribution:\n{df['fraudulent'].value_counts()}")
    return df

# ── Feature Engineering ────────────────────────────────────────────────────

def build_features(df):
    """Combine all text columns into a single feature string."""
    text_cols = ['title', 'company_profile', 'description', 'requirements', 'benefits']
    present   = [c for c in text_cols if c in df.columns]

    df[present] = df[present].fillna('')
    df['combined_text'] = df[present].apply(lambda row: ' '.join(row.values), axis=1)

    # If the real EMSCAD dataset is used, add extra numeric/boolean signals
    extra_cols = ['telecommuting', 'has_company_logo', 'has_questions']
    for col in extra_cols:
        if col in df.columns:
            df['combined_text'] += ' ' + col.replace('_', ' ') + ' ' + df[col].astype(str)

    return df['combined_text'], df['fraudulent'].astype(int)

# ── Train ──────────────────────────────────────────────────────────────────

def train(X_text, y):
    print("\n[INFO] Vectorising with TF-IDF...")
    vectorizer = TfidfVectorizer(
        max_features=8000,
        ngram_range=(1, 2),       # unigrams + bigrams
        sublinear_tf=True,        # log scaling of term frequency
        strip_accents='unicode',
        analyzer='word',
        min_df=1,
    )
    X = vectorizer.fit_transform(X_text)
    print(f"[INFO] Feature matrix: {X.shape[0]} samples × {X.shape[1]} features")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n[INFO] Training Logistic Regression classifier...")
    model = LogisticRegression(
        C=1.0,
        max_iter=1000,
        class_weight='balanced',   # handle class imbalance
        random_state=42,
    )
    model.fit(X_train, y_train)

    # ── Evaluation ──────────────────────────────────────────────────────
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 55)
    print("  MODEL EVALUATION RESULTS")
    print("=" * 55)
    print(f"  Accuracy       : {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Real', 'Fake']))
    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f"\n  5-Fold CV Accuracy: {cv_scores.mean() * 100:.2f}% ± {cv_scores.std() * 100:.2f}%")
    print("=" * 55)

    return model, vectorizer

# ── Save ───────────────────────────────────────────────────────────────────

def save_artifacts(model, vectorizer):
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model,      MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\n[INFO] Model saved     → {MODEL_PATH}")
    print(f"[INFO] Vectorizer saved → {VECTORIZER_PATH}")

# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 55)
    print("  JOBGUARD — ML MODEL TRAINER")
    print("=" * 55)

    df = load_data()
    X_text, y = build_features(df)
    model, vectorizer = train(X_text, y)
    save_artifacts(model, vectorizer)

    print("\n[OK] Training complete. Run `python app.py` to start the server.")

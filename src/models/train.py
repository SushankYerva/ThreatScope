"""
Training pipeline for ThreatScope.

Goal:
- Load labeled network flow data (e.g. CICIDS2017, UNSW-NB15).
- Select features consistent with FlowFeatureExtractor.
- Train ML model (XGBoost or RandomForest).
- Evaluate.
- Persist artifact for runtime inference.

Assumptions:
- Input dataset is a CSV with one row per flow.
- Columns include both numeric features and a string label.
- You are expected to preprocess raw public IDS datasets into that format
  in a notebook first. This script trains on that processed CSV.

This file does not download datasets. That keeps licensing clean.
"""

from __future__ import annotations
from typing import List, Tuple, Dict, Any
import argparse
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier


# These are the canonical features our runtime extractor produces.
# Order matters. Do not reorder without retraining and resaving.
FEATURE_ORDER = [
    "flow_duration_ms",
    "pkt_rate",
    "avg_pkt_size",
    "std_pkt_size",
    "bytes_total",
    "syn_count",
    "fin_count",
    "psh_count",
    "entropy_dst_port",
]


def load_dataset(csv_path: str,
                 label_column: str = "label") -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load dataset from CSV. Returns (X_df, y_series).

    Expectations:
    - csv_path has numeric columns matching FEATURE_ORDER
    - csv_path has a label column with attack class or "benign"
    """
    df = pd.read_csv(csv_path)

    # basic sanity
    missing = [f for f in FEATURE_ORDER if f not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing required features: {missing}")

    if label_column not in df.columns:
        raise ValueError(f"Dataset missing label column '{label_column}'")

    X = df[FEATURE_ORDER].astype(float)
    y = df[label_column].astype(str)

    return X, y


def build_model(model_type: str = "xgboost"):
    """
    Create an untrained model.
    Two options:
    - xgboost (faster inference than deep nets but strong accuracy)
    - rf (RandomForest) as fallback
    """
    model_type = model_type.lower()

    if model_type == "xgboost":
        # sensible defaults for tabular security flows
        return XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=1.0,
            n_jobs=-1,
            objective="multi:softprob",
        )

    if model_type == "rf":
        return RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            n_jobs=-1,
        )

    raise ValueError("model_type must be 'xgboost' or 'rf'")


def evaluate_model(
    model,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> Dict[str, Any]:
    """
    Return structured metrics for README / CI logs.
    We compute per-class precision/recall/f1 and macro averages.
    We also compute ROC AUC if multiclass -> macro average of one-vs-rest.
    """
    y_pred = model.predict(X_test)

    try:
        # predict_proba is needed for ROC AUC
        y_proba = model.predict_proba(X_test)
        # multiclass handling for roc_auc_score with OVR
        auc_macro = roc_auc_score(
            y_test,
            y_proba,
            multi_class="ovr",
            average="macro",
        )
    except Exception:
        auc_macro = None

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )

    report = classification_report(
        y_test, y_pred, output_dict=True, zero_division=0
    )

    return {
        "precision_macro": float(precision),
        "recall_macro": float(recall),
        "f1_macro": float(f1),
        "roc_auc_macro": float(auc_macro) if auc_macro is not None else None,
        "per_class": report,
    }


def save_artifacts(
    model,
    feature_order: List[str],
    out_dir: str = "model_artifacts",
    model_name: str = "model.joblib",
    feature_name: str = "feature_order.json",
    metrics_name: str = "metrics.json",
    metrics: Dict[str, Any] | None = None,
) -> None:
    """
    Persist model, feature order, and optional metrics.
    These files are what runtime inference uses.
    """
    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, p / model_name)

    with open(p / feature_name, "w", encoding="utf-8") as f:
        json.dump(feature_order, f, indent=2)

    if metrics is not None:
        with open(p / metrics_name, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)


def train_pipeline(
    csv_path: str,
    label_column: str,
    model_type: str,
    test_size: float,
    random_state: int,
    out_dir: str,
) -> Dict[str, Any]:
    """
    Full training:
    - load data
    - split train/test
    - train model
    - evaluate
    - save artifacts
    Returns metrics dict.
    """
    X, y = load_dataset(csv_path, label_column=label_column)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    model = build_model(model_type=model_type)
    model.fit(X_train, y_train)

    metrics = evaluate_model(model, X_test, y_test)

    save_artifacts(
        model=model,
        feature_order=FEATURE_ORDER,
        out_dir=out_dir,
        metrics=metrics,
    )

    return metrics


def main():
    """
    CLI entry for manual training runs.

    Example:
    python -m src.models.train \
        --data ./datasets/flows_labeled.csv \
        --label label \
        --model xgboost \
        --out ./model_artifacts
    """
    parser = argparse.ArgumentParser(
        description="Train ThreatScope intrusion detection model"
    )
    parser.add_argument(
        "--data",
        required=True,
        help="Path to preprocessed CSV (one row per flow, includes required features)",
    )
    parser.add_argument(
        "--label",
        default="label",
        help="Name of label column in CSV. Default: label",
    )
    parser.add_argument(
        "--model",
        default="xgboost",
        choices=["xgboost", "rf"],
        help="Model type",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of data for test split. Default: 0.2",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility. Default: 42",
    )
    parser.add_argument(
        "--out",
        default="model_artifacts",
        help="Output directory for model + feature_order.json",
    )

    args = parser.parse_args()

    metrics = train_pipeline(
        csv_path=args.data,
        label_column=args.label,
        model_type=args.model,
        test_size=args.test_size,
        random_state=args.random_state,
        out_dir=args.out,
    )

    # Print metrics to stdout for quick check
    # This is safe. It is not "background work". It runs now when you call main.
    print("Training complete.")
    print("Precision (macro):", metrics["precision_macro"])
    print("Recall (macro):", metrics["recall_macro"])
    print("F1 (macro):", metrics["f1_macro"])
    print("ROC-AUC (macro):", metrics["roc_auc_macro"])


if __name__ == "__main__":
    main()

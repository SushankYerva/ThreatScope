from typing import Dict, Any, List
import json
import joblib  # type: ignore


class ThreatClassifier:
    """
    Wraps a trained ML model used for intrusion detection.

    Assumes a model trained on fixed feature order.
    We store this order in a JSON file at train time.
    """

    def __init__(self, model_path: str, feature_order_path: str):
        """
        model_path: path to joblib model file
        feature_order_path: path to JSON list of feature names
        """
        self.model = joblib.load(model_path)
        with open(feature_order_path, "r", encoding="utf-8") as f:
            self.feature_order: List[str] = json.load(f)

        # class names inference
        # scikit models expose classes_
        if hasattr(self.model, "classes_"):
            self.class_labels = list(self.model.classes_)
        else:
            self.class_labels = ["benign", "malicious"]

    def _vectorize(self, feat: Dict[str, Any]) -> List[float]:
        """
        Convert feature dict into ordered numeric list for the model.
        Missing features default to 0.0
        """
        vec: List[float] = []
        for name in self.feature_order:
            val = feat.get(name, 0.0)
            try:
                vec.append(float(val))
            except Exception:
                vec.append(0.0)
        return vec

    def predict_flow(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        features: FeatureVector dict
        returns dict with predicted label and probability score
        """
        x_vec = [self._vectorize(features)]
        prob = None
        label_idx = None

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(x_vec)[0]
            # choose max prob
            max_i = max(range(len(probs)), key=lambda i: probs[i])
            prob = float(probs[max_i])
            label_idx = max_i
        else:
            pred = self.model.predict(x_vec)[0]
            # fallback
            label_idx = (
                self.class_labels.index(pred)
                if pred in self.class_labels
                else 0
            )
            prob = 1.0

        label_name = self.class_labels[label_idx] if label_idx is not None else "unknown"

        return {
            "label": str(label_name),
            "score": float(prob),
        }

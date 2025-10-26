from typing import Dict, Any, List
import json
import joblib  # type: ignore


class ThreatClassifier:
    """
    Wraps a trained ML model used for intrusion detection.

    After the label encoder change:
    - model predicts integer class indices
    - we map those integers back to human-readable labels using label_mapping.json
    """

    def __init__(self, model_path: str, feature_order_path: str, label_map_path: str | None = None):
        """
        model_path: path to joblib model file
        feature_order_path: path to JSON list of feature names
        label_map_path: path to JSON mapping of {class_index: class_label}
        """
        self.model = joblib.load(model_path)

        with open(feature_order_path, "r", encoding="utf-8") as f:
            self.feature_order: List[str] = json.load(f)

        # handle label mapping
        self.label_map = None
        if label_map_path is not None:
            with open(label_map_path, "r", encoding="utf-8") as f:
                raw_map = json.load(f)
            # keys may be strings in JSON; convert to int
            self.label_map = {int(k): v for (k, v) in raw_map.items()}

        # fallback if no label_map provided
        # model.classes_ will be numeric class ids after training
        if hasattr(self.model, "classes_"):
            self.class_ids = list(self.model.classes_)
        else:
            self.class_ids = [0, 1]

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

    def _decode_label(self, class_idx: int) -> str:
        """
        Convert numeric class index to human-readable label.
        """
        if self.label_map is not None:
            return self.label_map.get(class_idx, f"class_{class_idx}")
        # fallback: no mapping file
        return f"class_{class_idx}"

    def predict_flow(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        features: FeatureVector dict
        returns dict with predicted label and probability score
        """
        x_vec = [self._vectorize(features)]

        label_idx = None
        prob = None

        # get per-class probabilities
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(x_vec)[0]
            # pick class with max probability
            max_i = max(range(len(probs)), key=lambda i: probs[i])
            prob = float(probs[max_i])

            # map position in probs -> actual class id
            class_id = self.class_ids[max_i]
            label_idx = int(class_id)

        else:
            # fallback: use direct predict()
            pred_class_id = int(self.model.predict(x_vec)[0])
            label_idx = pred_class_id
            prob = 1.0

        human_label = self._decode_label(label_idx)

        return {
            "label": str(human_label),
            "score": float(prob),
        }

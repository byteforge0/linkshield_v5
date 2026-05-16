import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from linkshield.features import feature_vector, FEATURE_ORDER

DATA_PATH = os.path.join("data", "sample_urls.csv")
MODEL_PATH = os.path.join("models", "linkshield_model.joblib")

def main():
    df = pd.read_csv(DATA_PATH).dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    x = np.array([feature_vector(url) for url in df["url"]])
    y = df["label"].values
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=.25, random_state=42, stratify=y)
    model = VotingClassifier(
        estimators=[
            ("rf", RandomForestClassifier(n_estimators=500, random_state=42, class_weight="balanced")),
            ("et", ExtraTreesClassifier(n_estimators=500, random_state=42, class_weight="balanced")),
            ("lr", Pipeline([("scaler", StandardScaler()), ("clf", LogisticRegression(max_iter=4000, class_weight="balanced"))]))
        ],
        voting="soft"
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    print("Feature count:", len(FEATURE_ORDER))
    print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
    print("ROC AUC:", round(roc_auc_score(y_test, probabilities), 4))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))
    print(classification_report(y_test, predictions, target_names=["legitimate", "scam_or_phishing"]))
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to: {MODEL_PATH}")

if __name__ == "__main__":
    main()

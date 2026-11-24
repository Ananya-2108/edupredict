"""
EduPredict - Machine Learning Training and Evaluation Pipeline
Algorithm comparison: Random Forest, Logistic Regression, Decision Tree
Evaluates Accuracy, Precision, Recall, F1-Score, and Confusion Matrix
Saves the best model for Flask inference.
"""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler

def generate_synthetic_academic_dataset(num_samples=1200):
    np.random.seed(42)
    
    # 1. Attendance percentage (45% - 100%)
    attendance = np.random.uniform(45, 100, num_samples)
    
    # 2. Internal assessment marks (out of 100, 30 - 98)
    internal_marks = np.random.uniform(30, 98, num_samples)
    
    # 3. Assignment completion percentage (35% - 100%)
    assignments = np.random.uniform(35, 100, num_samples)
    
    # 4. Previous semester score (out of 100, 35 - 99)
    prev_score = np.random.uniform(35, 99, num_samples)
    
    # 5. Daily study hours (1.0 to 9.0 hours)
    study_hours = np.random.uniform(1.0, 8.5, num_samples)
    
    # 6. Classroom participation score (1 to 10)
    participation = np.random.uniform(2.0, 10.0, num_samples)
    
    # Composite Academic Index score
    composite = (
        0.25 * attendance +
        0.30 * internal_marks +
        0.15 * assignments +
        0.20 * prev_score +
        1.5 * study_hours +
        0.8 * participation
    )
    
    # Add minor noise
    composite += np.random.normal(0, 3.5, num_samples)
    
    # Targets:
    # 0 = At-Risk Student (composite < 62 or attendance < 65 or internal_marks < 50)
    # 1 = Average Performer (62 <= composite < 80)
    # 2 = High Performer (composite >= 80)
    categories = []
    risk_levels = []
    
    for i in range(num_samples):
        att = attendance[i]
        int_m = internal_marks[i]
        comp = composite[i]
        
        if comp < 63 or (att < 65 and int_m < 50) or int_m < 45:
            categories.append(0) # At-Risk
            risk_levels.append('High' if att < 60 or int_m < 40 else 'Medium')
        elif comp >= 80 and att >= 75 and int_m >= 70:
            categories.append(2) # High Performer
            risk_levels.append('Low')
        else:
            categories.append(1) # Average Performer
            risk_levels.append('Low' if att >= 75 else 'Medium')
            
    df = pd.DataFrame({
        'attendance': np.round(attendance, 1),
        'internal_marks': np.round(internal_marks, 1),
        'assignment_completion': np.round(assignments, 1),
        'previous_semester_score': np.round(prev_score, 1),
        'study_hours': np.round(study_hours, 1),
        'participation': np.round(participation, 1),
        'target_category': categories,
        'risk_level': risk_levels
    })
    return df

def train_and_evaluate_models():
    print("Generating academic dataset for model training...")
    df = generate_synthetic_academic_dataset()
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(current_dir, 'student_academic_dataset.csv')
    df.to_csv(data_path, index=False)
    print(f"Saved dataset to {data_path}")
    
    feature_cols = ['attendance', 'internal_marks', 'assignment_completion', 'previous_semester_score', 'study_hours', 'participation']
    X = df[feature_cols]
    y = df['target_category']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42),
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
        'Decision Tree': DecisionTreeClassifier(max_depth=6, random_state=42)
    }
    
    eval_results = {}
    best_model_name = 'Random Forest'
    best_score = 0
    
    for name, model in models.items():
        if name == 'Logistic Regression':
            model.fit(X_train_scaled, y_train)
            y_pred = model.predict(X_test_scaled)
        else:
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted')
        rec = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        eval_results[name] = {
            'accuracy': round(acc * 100, 2),
            'precision': round(prec * 100, 2),
            'recall': round(rec * 100, 2),
            'f1_score': round(f1 * 100, 2),
            'confusion_matrix': cm
        }
        
        if acc > best_score:
            best_score = acc
            best_model_name = name
            
    print("Training Results Summary:")
    for name, metrics in eval_results.items():
        print(f"[{name}] Accuracy: {metrics['accuracy']}%, F1: {metrics['f1_score']}%")
        
    # Save Random Forest Model, Scaler, and Evaluation Metrics
    rf_model = models['Random Forest']
    joblib.dump(rf_model, os.path.join(current_dir, 'edupredict_rf_model.pkl'))
    joblib.dump(scaler, os.path.join(current_dir, 'edupredict_scaler.pkl'))
    joblib.dump(eval_results, os.path.join(current_dir, 'model_evaluation.pkl'))
    print("Models and evaluation metrics successfully serialized!")

if __name__ == '__main__':
    train_and_evaluate_models()

def get_threat_classification(risk_score):
    """
    Standardizes and unifies risk classification based on a numeric risk score (0-100).
    
    Categories:
    - 0-24: Safe
    - 25-39: Low Risk
    - 40-69: Suspicious
    - 70-89: High Risk
    - 90-100: Malicious
    """
    score = int(risk_score)
    if score >= 90:
        return "Malicious"
    elif score >= 70:
        return "High Risk"
    elif score >= 40:
        return "Suspicious"
    elif score >= 25:
        return "Low Risk"
    else:
        return "Safe"

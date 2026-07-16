from utils.analyst.knowledge_base import ATTACK_TYPES
from utils.analyst.attack_classifier import classify_attack
from utils.analyst.evidence_collector import collect_evidence
from utils.analyst.mitre_mapper import map_to_mitre
from utils.analyst.recommendation_engine import get_prevention
from utils.analyst.incident_response_engine import get_incident_response

def build_risk_assessment(risk_score, classification, attack_type):
    """
    Builds the risk assessment structure.
    """
    impact = "High" if classification in ["Malicious", "High Risk"] else "Medium" if classification == "Suspicious" else "Low"
    
    if attack_type == "Clean / No Threat Detected":
        return {
            "risk_level": "Safe",
            "confidence_score": risk_score,
            "business_impact": "None.",
            "personal_impact": "None.",
            "likelihood": "None",
            "severity": "None"
        }
        
    return {
        "risk_level": classification,
        "confidence_score": risk_score,
        "business_impact": f"{impact} potential impact to corporate assets and data.",
        "personal_impact": f"{impact} potential impact to personal privacy and credentials.",
        "likelihood": impact,
        "severity": classification
    }

def build_analyst_report(scan_type, features, risk_score, classification, osint_data=None, nlp_analysis=None, screenshot_category=None, screenshot_explanations=None):
    """
    Orchestrates all sub-modules to generate a comprehensive AI Cybersecurity Analyst report.
    """
    attack_type = classify_attack(scan_type, features, risk_score, classification, osint_data, nlp_analysis, screenshot_category)
    
    if attack_type == "Clean / No Threat Detected":
        description = {
            "what": "No active threat detected.",
            "how_attackers_do_it": "N/A",
            "what_they_steal": "N/A",
            "who_is_targeted": "N/A",
            "how_it_spreads": "N/A",
            "why_dangerous": "N/A"
        }
        evidence = ["Insufficient evidence of malicious activity."]
        risk_assessment = build_risk_assessment(risk_score, classification, attack_type)
        mitre = []
        prevention = {
            "what_to_do": ["No Prevention Actions Required"],
            "what_not_to_do": ["N/A"]
        }
        ir = {
            "containment": ["N/A"],
            "recovery": ["N/A"],
            "credential_reset": ["N/A"],
            "reporting": ["No Incident Response Required"]
        }
    else:
        # Get description safely
        if attack_type in ATTACK_TYPES:
            description = ATTACK_TYPES[attack_type]
        else:
            description = {
                "what": "An unidentified or low-confidence threat pattern.",
                "how_attackers_do_it": "Techniques vary depending on the specific campaign.",
                "what_they_steal": "Potentially sensitive information or credentials.",
                "who_is_targeted": "Users and organizations.",
                "how_it_spreads": "Via email, web, or social engineering.",
                "why_dangerous": "Can lead to unauthorized access or data loss."
            }
            
        evidence = collect_evidence(scan_type, features, risk_score, classification, osint_data, nlp_analysis, screenshot_explanations)
        
        if not evidence:
            evidence = ["Insufficient evidence to confirm specific attack vectors."]
            
        risk_assessment = build_risk_assessment(risk_score, classification, attack_type)
        mitre = map_to_mitre(attack_type)
        prevention = get_prevention(attack_type, classification)
        ir = get_incident_response(attack_type, classification, scan_type)
    
    return {
        "attack_type": attack_type,
        "attack_description": description,
        "detection_evidence": evidence,
        "risk_assessment": risk_assessment,
        "mitre_mapping": mitre,
        "prevention": prevention,
        "incident_response": ir
    }

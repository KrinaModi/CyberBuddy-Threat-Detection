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
    
    # --- NEW ENTERPRISE SOC DASHBOARD FIELDS ---
    
    # 1. Build IOCs
    iocs = []
    if osint_data:
        if osint_data.get("ip") and osint_data.get("ip") != "Not resolved":
            iocs.append({"type": "IP Address", "value": osint_data["ip"]})
        if osint_data.get("registrar") and osint_data.get("registrar") != "Unknown Registrar":
            iocs.append({"type": "Registrar", "value": osint_data["registrar"]})
            
    if nlp_analysis and nlp_analysis.get("top_features"):
        keywords = [item["word"] for item in nlp_analysis["top_features"] if item["contribution"] > 0.05]
        if keywords:
            iocs.append({"type": "Suspicious Keywords", "value": ", ".join(keywords)})
            
    if features.get("is_ip_address"):
        iocs.append({"type": "Format Indicator", "value": "Raw IP Address"})
        
    if scan_type == "URL" and osint_data:
        # If it's a URL, we might not have the raw target here directly, but we can assume IOCs
        iocs.append({"type": "Target Type", "value": "URL / Domain"})
    elif scan_type == "EMAIL":
        iocs.append({"type": "Target Type", "value": "Email Body / Content"})

    if not iocs:
        iocs.append({"type": "System", "value": "No specific IOCs extracted."})

    # 2. Parse Evidence Table
    evidence_table = []
    for ev in evidence:
        if ev.startswith("[") and "]" in ev:
            source = ev[1:ev.find("]")]
            reason = ev[ev.find("]")+1:].strip()
            confidence = "High" if source in ["VT", "DNS", "RDAP", "OCR/CV"] else "Medium" if source in ["GEOIP", "STRUCT", "PROTOCOL"] else "Low"
        else:
            source = "SYSTEM"
            reason = ev
            confidence = "Low"
            
        evidence_table.append({
            "evidence": reason,
            "source": source,
            "confidence": confidence,
            "reason": reason
        })

    # 3. Timeline
    incident_timeline = [
        {"step": "Input Received", "status": "Completed"},
        {"step": "Preprocessing & Feature Extraction", "status": "Completed"},
        {"step": "Threat Detection & ML Inference", "status": "Completed"},
        {"step": "Evidence Collection & OSINT", "status": "Completed"},
        {"step": "MITRE ATT&CK Mapping", "status": "Completed"},
        {"step": "Risk Score Calculation", "status": "Completed"},
        {"step": "Analyst Report Generated", "status": "Completed"}
    ]

    # 4. Executive Summary
    executive_summary = {
        "what_happened": description.get("what", "A security scan was executed."),
        "why_dangerous": description.get("why_dangerous", "Could potentially compromise systems or steal sensitive information."),
        "current_status": classification
    }
    
    # 5. Analyst Findings
    analyst_findings = {
        "observed_behavior": description.get("how_attackers_do_it", "No specific behavior observed."),
        "why_suspicious": "Multiple indicators of compromise were flagged during static and dynamic analysis." if classification != "Safe" else "No suspicious indicators were flagged.",
        "potential_impact": risk_assessment["business_impact"],
        "likelihood": risk_assessment["likelihood"]
    }
    
    # 6. Technical Analysis & Conclusion for printable report
    technical_analysis = f"The artifact was analyzed using the {scan_type} pipeline. The system derived a risk score of {risk_score} mapping to {classification}. Structural features and ML confidence yielded {risk_assessment['confidence_score']}% certainty."
    conclusion = f"The investigation concludes with a {classification} verdict. Playbooks and recommended actions should be followed accordingly."

    return {
        "attack_type": attack_type,
        "attack_description": description,
        "detection_evidence": evidence,
        "risk_assessment": risk_assessment,
        "mitre_mapping": mitre,
        "prevention": prevention,
        "incident_response": ir,
        "iocs": iocs,
        "evidence_table": evidence_table,
        "incident_timeline": incident_timeline,
        "executive_summary": executive_summary,
        "analyst_findings": analyst_findings,
        "technical_analysis": technical_analysis,
        "conclusion": conclusion
    }

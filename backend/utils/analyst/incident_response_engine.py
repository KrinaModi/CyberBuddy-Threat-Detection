from utils.analyst.knowledge_base import INCIDENT_RESPONSE

def get_incident_response(attack_type, classification, scan_type):
    """
    Returns the incident response playbook for a given attack type.
    """
    if attack_type in INCIDENT_RESPONSE:
        return INCIDENT_RESPONSE[attack_type]
    return INCIDENT_RESPONSE["default"]

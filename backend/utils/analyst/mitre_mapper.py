from utils.analyst.knowledge_base import MITRE_MAPPINGS

def map_to_mitre(attack_type):
    """
    Returns the MITRE ATT&CK mappings for a given attack type.
    """
    if attack_type in MITRE_MAPPINGS:
        return MITRE_MAPPINGS[attack_type]
    return []

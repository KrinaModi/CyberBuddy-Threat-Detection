from utils.analyst.knowledge_base import PREVENTION_PLAYBOOKS

def get_prevention(attack_type, classification):
    """
    Returns the prevention playbook for a given attack type.
    """
    if attack_type in PREVENTION_PLAYBOOKS:
        return PREVENTION_PLAYBOOKS[attack_type]
    return PREVENTION_PLAYBOOKS["default"]

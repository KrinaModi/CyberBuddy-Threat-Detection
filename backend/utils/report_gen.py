def get_report_meta(scan):
    """
    Returns metadata formatted for printable reports.
    """
    return {
        "report_id": f"{scan.id}-{scan.timestamp.strftime('%Y%m%d%H%M') if scan.timestamp else '0000'}",
        "engine_version": "SOC_GRADE_v2",
        "export_allowed": True
    }

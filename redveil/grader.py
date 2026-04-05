"""Grader system for RedVeil tasks.

Each grader checks the environment's internal game state and returns
a score from 0.0 to 1.0 based on milestone progression.

Honeypot penalties reduce score. Efficiency bonuses reward clean play.
"""

from .tasks import ALL_TASKS


def grade_task(game_state: dict) -> float:
    """Grade a completed task based on its game state.

    Args:
        game_state: Dictionary from RedVeilEnvironment.get_game_state()

    Returns:
        Score from 0.0 to 1.0
    """
    task_id = game_state.get("task_id")
    if task_id == "easy_recon":
        return grade_easy(game_state)
    elif task_id == "medium_deception":
        return grade_medium(game_state)
    elif task_id == "hard_chain":
        return grade_hard(game_state)
    elif task_id == "expert_chain":
        return grade_expert(game_state)
    return 0.0


def _honeypot_penalty(state: dict) -> float:
    """Calculate penalty for interacting with honeypots."""
    honeypots_hit = len(state.get("flagged_honeypots", []))
    return honeypots_hit * 0.05


def grade_easy(state: dict) -> float:
    """Grade Task 1: Signal vs Noise.

    Milestones:
        scanned_port       -> 0.1
        identified_1_real  -> 0.3
        identified_2_real  -> 0.6
        identified_all_3_clean -> 1.0

    Penalty: false positives (identifying noise as real) reduce score.
    """
    real_ports = set(state.get("identified_real_ports", []))
    fake_ports = set(state.get("identified_fake_ports", []))
    scanned = bool(state.get("scan_counts"))

    task = ALL_TASKS["easy_recon"]
    true_real = set(task.real_port_ids)
    correct = real_ports & true_real
    false_positives = len(fake_ports)

    if len(correct) >= 3 and false_positives == 0:
        return 1.0
    elif len(correct) >= 2:
        score = 0.6
        score -= false_positives * 0.15
        return max(0.1, round(score, 2))
    elif len(correct) >= 1:
        score = 0.3
        score -= false_positives * 0.15
        return max(0.1, round(score, 2))
    elif scanned:
        return 0.1
    return 0.0


def grade_medium(state: dict) -> float:
    """Grade Task 2: Truth vs Deception.

    Milestones:
        discovered_endpoint -> 0.15
        found_real_vuln     -> 0.4
        exploited_vuln      -> 0.7
        flagged_honeypot    -> 1.0

    Penalty for honeypot interactions.
    """
    discovered = bool(state.get("discovered_endpoints"))
    vuln_found = state.get("vuln_found", False)
    exploit_success = state.get("exploit_success", False)
    flagged_honeypots = state.get("flagged_honeypots", [])

    penalty = _honeypot_penalty(state)

    if exploit_success and flagged_honeypots:
        return max(0.15, round(1.0 - penalty, 2))
    elif exploit_success:
        return max(0.15, round(0.7 - penalty, 2))
    elif vuln_found:
        return max(0.1, round(0.4 - penalty, 2))
    elif discovered:
        return 0.15
    return 0.0


def grade_hard(state: dict) -> float:
    """Grade Task 3: Full Gauntlet.

    Milestones:
        useful_recon    -> 0.05
        found_config    -> 0.15
        found_real_vuln -> 0.3
        exploited_vuln  -> 0.55
        extracted_creds -> 0.75
        admin_login     -> 1.0

    Penalty for honeypot interactions.
    """
    has_recon = bool(state.get("scan_counts")) or bool(state.get("discovered_endpoints"))
    config_found = state.get("config_fetched", False)
    vuln_found = state.get("vuln_found", False)
    exploit_success = state.get("exploit_success", False)
    creds_extracted = state.get("creds_extracted", False)
    admin_login = state.get("admin_login", False)

    penalty = _honeypot_penalty(state)

    if admin_login:
        return max(0.3, round(1.0 - penalty, 2))
    elif creds_extracted:
        return max(0.15, round(0.75 - penalty, 2))
    elif exploit_success:
        return max(0.1, round(0.55 - penalty, 2))
    elif vuln_found:
        return max(0.05, round(0.3 - penalty, 2))
    elif config_found:
        return 0.15
    elif has_recon:
        return 0.05
    return 0.0


def grade_expert(state: dict) -> float:
    """Grade Task 4: Information Chain -- Privilege Escalation.

    Milestones (each requires the previous):
        useful_recon         -> 0.05
        info_disclosure      -> 0.12
        low_priv_access      -> 0.25
        acquired_token       -> 0.4
        extracted_admin_creds -> 0.7
        admin_login          -> 1.0

    Heavy penalty for honeypot interactions.
    """
    has_recon = bool(state.get("scan_counts")) or bool(state.get("discovered_endpoints"))
    info_disclosure = state.get("config_fetched", False) or bool(state.get("hidden_endpoints_found"))
    low_priv = state.get("low_priv_login", False)
    has_token = state.get("session_token_acquired", False)
    creds_extracted = state.get("creds_extracted", False)
    admin_login = state.get("admin_login", False)

    penalty = _honeypot_penalty(state) * 1.5  # Heavier penalty on expert

    if admin_login:
        return max(0.25, round(1.0 - penalty, 2))
    elif creds_extracted:
        return max(0.12, round(0.7 - penalty, 2))
    elif has_token:
        return max(0.1, round(0.4 - penalty, 2))
    elif low_priv:
        return max(0.05, round(0.25 - penalty, 2))
    elif info_disclosure:
        return 0.12
    elif has_recon:
        return 0.05
    return 0.0

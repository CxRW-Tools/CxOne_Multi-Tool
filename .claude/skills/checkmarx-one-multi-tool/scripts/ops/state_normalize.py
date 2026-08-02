"""
Normalize triage state and severity: accept any input (case-insensitive), display in
normal capitalization ("Not Exploitable"), and send the correct format per API.

- Input (config or API): any case/format; matching is case-insensitive.
- Display and config file values: normal capitalization ("Not Exploitable", "Critical").
- SAST/IaC APIs: UPPER_SNAKE (TO_VERIFY, NOT_EXPLOITABLE, CRITICAL).
- SCA risk API: PascalCase (ToVerify, NotExploitable).
- SCA package API: Muted, Snooze, Monitored.
"""


def _canonical(s: str) -> str:
    """Normalize any state/severity string to a canonical key for lookup (lower, no spaces/underscores)."""
    if not s or not isinstance(s, str):
        return ""
    t = (s or "").strip().lower().replace("_", " ").replace("-", " ")
    return "".join(t.split())


def is_to_verify(state: str) -> bool:
    """True if a result's state is 'To Verify' (untriaged), across all engine
    spellings (TO_VERIFY / ToVerify / 'To Verify'). Used to ensure triage only
    ever acts on untriaged findings, so repeated agent passes don't re-triage or
    flip findings a prior pass already set. An empty/unknown state is treated as
    NOT To-Verify (safer: we skip it rather than risk clobbering a triaged one)."""
    return _canonical(state) == "toverify"


# Canonical key -> display (normal capitalization: first letter cap per word)
_STATE_DISPLAY = {
    "toverify": "To Verify",
    "notexploitable": "Not Exploitable",
    "proposednotexploitable": "Proposed Not Exploitable",
    "confirmed": "Confirmed",
    "urgent": "Urgent",
    "muted": "Muted",
    "snooze": "Snooze",
    "monitored": "Monitored",
}

# Canonical key -> SAST/IaC API (UPPER_SNAKE)
_SAST_IAC_STATE = {
    "toverify": "TO_VERIFY",
    "notexploitable": "NOT_EXPLOITABLE",
    "proposednotexploitable": "PROPOSED_NOT_EXPLOITABLE",
    "confirmed": "CONFIRMED",
    "urgent": "URGENT",
}

# Canonical key -> SCA risk API (PascalCase)
_SCA_RISK_STATE = {
    "toverify": "ToVerify",
    "notexploitable": "NotExploitable",
    "proposednotexploitable": "ProposedNotExploitable",
    "confirmed": "Confirmed",
    "urgent": "Urgent",
}

# Canonical key -> SCA package API (PascalCase)
_SCA_PACKAGE_STATE = {
    "muted": "Muted",
    "snooze": "Snooze",
    "monitored": "Monitored",
}


def _state_to_display(canonical_key: str, fallback: str) -> str:
    """Return normal-capitalization display form for state."""
    return _STATE_DISPLAY.get(canonical_key, fallback.strip().title() if fallback else "")


def sast_iac_state_to_api(any_input: str) -> str:
    """Convert any state input to SAST/IaC API form (UPPER_SNAKE)."""
    c = _canonical(any_input)
    return _SAST_IAC_STATE.get(c, (any_input or "").strip().upper().replace(" ", "_"))


def sast_iac_state_to_display(api_state: str) -> str:
    """Convert SAST/IaC API state to normal capitalization for display."""
    c = _canonical(api_state)
    return _state_to_display(c, api_state)


def sca_risk_state_to_api(any_input: str) -> str:
    """Convert any state input to SCA risk API form (PascalCase)."""
    c = _canonical(any_input)
    return _SCA_RISK_STATE.get(c, (any_input or "").strip().title().replace(" ", ""))


def sca_risk_state_to_display(api_state: str) -> str:
    """Convert SCA risk API state to normal capitalization for display."""
    c = _canonical(api_state)
    return _state_to_display(c, api_state)


def sca_package_state_to_api(any_input: str) -> str:
    """Convert any state input to SCA package API form (Muted, Snooze, Monitored)."""
    c = _canonical(any_input)
    return _SCA_PACKAGE_STATE.get(c, (any_input or "").strip().capitalize())


def sca_package_state_to_display(api_state: str) -> str:
    """Convert SCA package API state to normal capitalization for display."""
    c = _canonical(api_state)
    return _state_to_display(c, api_state)


def severity_to_api_sast_iac(any_input: str) -> str:
    """Convert any severity input to SAST/IaC API form (UPPER_SNAKE)."""
    s = (any_input or "").strip().upper().replace(" ", "_")
    return s if s else ""


def severity_normalize_for_match(severity: str) -> str:
    """Normalize severity for rule matching (case-insensitive). Accept any input."""
    return (severity or "").strip().upper().replace(" ", "_")


def severity_to_display(severity: str) -> str:
    """Convert severity to normal capitalization for display (Critical, High, etc.)."""
    s = (severity or "").strip()
    if not s:
        return ""
    return s.upper().replace("_", " ").title()

"""
SOC Detection Lab Engine Package
"""
from .parser import normalize_windows_process_creation, normalize_linux_sudo_event
from .rule_matcher import SigmaRule, load_rules

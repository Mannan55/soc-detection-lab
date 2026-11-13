"""
Log normalization engine for SOC Detection Lab.
Standardizes heterogeneous Windows and Linux security telemetry into normalized dictionaries.

Strictly zero em dashes (U+2014).
"""

import re
from typing import Dict, Any, Optional


def normalize_windows_process_creation(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes Windows Security Event 4688 or Sysmon Event 1 process creation events.
    """
    event_data = raw_event.get("EventData", raw_event)
    
    image = event_data.get("NewProcessName") or event_data.get("Image") or ""
    command_line = event_data.get("CommandLine") or ""
    parent_image = event_data.get("ParentProcessName") or event_data.get("ParentImage") or ""
    user = event_data.get("TargetUserName") or event_data.get("User") or ""
    process_id = event_data.get("NewProcessId") or event_data.get("ProcessId") or ""
    
    return {
        "event_id": str(raw_event.get("EventID", 4688)),
        "channel": "Security",
        "Image": image,
        "CommandLine": command_line,
        "ParentImage": parent_image,
        "User": user,
        "ProcessId": str(process_id),
        "timestamp": raw_event.get("TimeCreated", "")
    }


def normalize_linux_sudo_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes Linux sudo execution events from /var/log/auth.log or syslog.
    Handles both pre-parsed JSON and raw syslog messages.
    """
    message = raw_event.get("message", "")
    user = raw_event.get("user", "")
    target_user = raw_event.get("target_user", "root")
    command = raw_event.get("command", "")
    pwd = raw_event.get("pwd", "")

    # If raw syslog line provided, parse sudo format:
    # "sudo:    user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
    if not command and "COMMAND=" in message:
        m_user = re.search(r"sudo:\s+([^\s:]+)\s*:", message)
        if m_user:
            user = m_user.group(1)
        
        m_target = re.search(r"USER=([^\s;]+)", message)
        if m_target:
            target_user = m_target.group(1)
            
        m_pwd = re.search(r"PWD=([^\s;]+)", message)
        if m_pwd:
            pwd = m_pwd.group(1)

        m_cmd = re.search(r"COMMAND=(.*)$", message)
        if m_cmd:
            command = m_cmd.group(1).strip()

    return {
        "log_type": "linux_auth",
        "facility": "authpriv",
        "User": user,
        "TargetUser": target_user,
        "Command": command,
        "WorkingDir": pwd,
        "Message": message,
        "timestamp": raw_event.get("timestamp", "")
    }

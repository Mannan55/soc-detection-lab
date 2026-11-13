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


def normalize_windows_logon_failure(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes Windows Security Event 4625 failed logon attempts.
    Extracts authentication failure parameters, logon types, and status codes.
    """
    event_data = raw_event.get("EventData", raw_event)

    target_user = (
        event_data.get("TargetUserName")
        or event_data.get("TargetUser")
        or event_data.get("User")
        or ""
    )
    workstation = (
        event_data.get("WorkstationName")
        or event_data.get("Workstation")
        or ""
    )
    ip_address = (
        event_data.get("IpAddress")
        or event_data.get("SourceIp")
        or event_data.get("IpPort")
        or ""
    )
    logon_type = str(
        event_data.get("LogonType")
        or raw_event.get("LogonType")
        or ""
    )
    status = (
        event_data.get("Status")
        or raw_event.get("Status")
        or ""
    )
    sub_status = (
        event_data.get("SubStatus")
        or raw_event.get("SubStatus")
        or ""
    )
    failure_reason = (
        event_data.get("FailureReason")
        or event_data.get("StatusDescription")
        or ""
    )

    return {
        "event_id": str(raw_event.get("EventID", 4625)),
        "channel": "Security",
        "TargetUserName": target_user,
        "WorkstationName": workstation,
        "IpAddress": ip_address,
        "LogonType": logon_type,
        "Status": status,
        "SubStatus": sub_status,
        "FailureReason": failure_reason,
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


def normalize_linux_ssh_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes Linux sshd authentication events from /var/log/auth.log or journalctl.
    Handles failed passwords, invalid users, successful authentications, and disconnections.
    """
    message = raw_event.get("message", "")
    app = raw_event.get("app", "sshd")
    event_type = raw_event.get("event", "")
    user = raw_event.get("user", "")
    source_ip = raw_event.get("source_ip", "")
    port = str(raw_event.get("port", ""))

    # If syslog message format is provided, parse via regex
    if message and not event_type:
        # Example 1: Failed password for invalid user admin from 192.168.1.150 port 54822 ssh2
        m_failed_inv = re.search(
            r"Failed password for invalid user\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)",
            message
        )
        if m_failed_inv:
            event_type = "Failed password"
            user = m_failed_inv.group(1)
            source_ip = m_failed_inv.group(2)
            port = m_failed_inv.group(3)
        else:
            # Example 2: Failed password for root from 192.168.1.150 port 54822 ssh2
            m_failed = re.search(
                r"Failed password for\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)",
                message
            )
            if m_failed:
                event_type = "Failed password"
                user = m_failed.group(1)
                source_ip = m_failed.group(2)
                port = m_failed.group(3)
            else:
                # Example 3: Invalid user guest from 172.16.5.22 port 50100
                m_inv = re.search(
                    r"Invalid user\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)",
                    message
                )
                if m_inv:
                    event_type = "Invalid user"
                    user = m_inv.group(1)
                    source_ip = m_inv.group(2)
                    port = m_inv.group(3)
                else:
                    # Example 4: Accepted publickey for ubuntu from 10.0.1.5 port 43100
                    m_acc = re.search(
                        r"Accepted\s+([^\s]+)\s+for\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)",
                        message
                    )
                    if m_acc:
                        event_type = f"Accepted {m_acc.group(1)}"
                        user = m_acc.group(2)
                        source_ip = m_acc.group(3)
                        port = m_acc.group(4)

    return {
        "log_type": "linux_auth",
        "facility": "auth",
        "app": app,
        "Event": event_type,
        "User": user,
        "SourceIp": source_ip,
        "Port": port,
        "Message": message,
        "timestamp": raw_event.get("timestamp", "")
    }


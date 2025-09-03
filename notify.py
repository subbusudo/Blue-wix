#!/usr/bin/env python3
"""
Notifier module: Email (Gmail SMTP) and WhatsApp (Twilio) notifications.

Notes:
- Gmail requires an App Password if 2FA is enabled.
- Twilio WhatsApp requires sandbox or approved senders. Use numbers like "whatsapp:+1234567890".
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List
import logging

try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Notifier:
    def __init__(self, config: Dict[str, Any], logger_name: str = __name__):
        self.config = config.get('notifications', {})
        self.logger = logging.getLogger(logger_name)

        self.enabled = bool(self.config.get('enabled', False))
        self.min_severity = self.config.get('min_severity', 'HIGH').upper()

        # Email
        self.email_cfg = self.config.get('email', {})
        # WhatsApp
        self.whatsapp_cfg = self.config.get('whatsapp', {})

    def maybe_notify(self, alert: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        sev = alert.get('severity', 'LOW').upper()
        if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK.get(self.min_severity, 0):
            return

        # Build message
        subject = f"IDS Alert: {alert.get('type')} ({sev})"
        lines = [
            f"Type: {alert.get('type')}",
            f"Severity: {sev}",
            f"Description: {alert.get('description')}",
            f"Source: {alert.get('source', 'unknown')}",
        ]
        details = alert.get('details', {})
        if details:
            lines.append(f"Details: {details}")
        body = "\n".join(lines)

        # Send via enabled channels
        try:
            if self.email_cfg.get('enabled', False):
                self._send_email(subject, body)
        except Exception as e:
            self.logger.error(f"Email notification failed: {e}")

        try:
            if self.whatsapp_cfg.get('enabled', False):
                self._send_whatsapp(body)
        except Exception as e:
            self.logger.error(f"WhatsApp notification failed: {e}")

    def _send_email(self, subject: str, body: str) -> None:
        host = self.email_cfg.get('smtp_host', 'smtp.gmail.com')
        port = int(self.email_cfg.get('smtp_port', 587))
        use_tls = bool(self.email_cfg.get('use_tls', True))
        username = self.email_cfg.get('username')
        password = self.email_cfg.get('app_password')
        recipients: List[str] = self.email_cfg.get('to', [])
        if not (username and password and recipients):
            raise ValueError('Email configuration incomplete')

        msg = MIMEMultipart()
        msg['From'] = username
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(host, port, timeout=15) as server:
            if use_tls:
                server.starttls()
            server.login(username, password)
            server.sendmail(username, recipients, msg.as_string())

    def _send_whatsapp(self, body: str) -> None:
        if TwilioClient is None:
            raise RuntimeError('twilio not installed; pip install twilio')
        sid = self.whatsapp_cfg.get('account_sid')
        token = self.whatsapp_cfg.get('auth_token')
        from_number = self.whatsapp_cfg.get('from_number')
        to_numbers: List[str] = self.whatsapp_cfg.get('to_numbers', [])
        if not (sid and token and from_number and to_numbers):
            raise ValueError('WhatsApp configuration incomplete')

        client = TwilioClient(sid, token)
        for to in to_numbers:
            client.messages.create(
                body=body,
                from_=from_number,
                to=to
            )



"""
core/email_sender.py

Sends transactional emails over SMTP (stdlib only, no new dependencies).
Env: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM.

This file has functions for sending email in these scenarios : email verification with mailed otp, to email the password reset link, success message 
after resseting password successfully
"""

import html
import os
import smtplib
import ssl
from email.message import EmailMessage


def _send(msg: EmailMessage) -> None:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]

    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=10) as smtp:
            smtp.login(user, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.starttls(context=context)
            smtp.login(user, password)
            smtp.send_message(msg)


def _sender() -> str:
    return os.environ.get("SMTP_FROM", os.environ["SMTP_USER"])


def send_otp_email(to_email: str, otp: str, valid_seconds: int) -> None:
    minutes = max(1, round(valid_seconds / 60))
    msg = EmailMessage()
    msg["Subject"] = "Your verification code"
    msg["From"] = _sender()
    msg["To"] = to_email
    msg.set_content(
        f"Your verification code is {otp}.\n\n"
        f"It expires in {minutes} minute{'s' if minutes != 1 else ''}. "
        "If you did not request this, you can ignore this email."
    )
    _send(msg)


def send_password_reset_email(
    to_email: str, name: str, reset_url: str, valid_minutes: int
) -> None:
    display_name = name or "there"
    safe_name = html.escape(display_name)
    safe_url = html.escape(reset_url, quote=True)

    msg = EmailMessage()
    msg["Subject"] = "Reset your password"
    msg["From"] = _sender()
    msg["To"] = to_email

    msg.set_content(
        f"Hi {display_name},\n\n"
        f"We received a request to reset your password. Use the link below "
        f"(valid for {valid_minutes} minutes, single use):\n\n"
        f"{reset_url}\n\n"
        "If you did not request this, you can safely ignore this email. "
        "Your password will not change."
    )
    msg.add_alternative(
        f"""\
<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
  <p>Hi {safe_name},</p>
  <p>We received a request to reset your password. This link is valid for
     <b>{valid_minutes} minutes</b> and can be used only once.</p>
  <p style="margin:24px 0">
    <a href="{safe_url}"
       style="background:#1a56db;color:#fff;padding:12px 24px;
              border-radius:6px;text-decoration:none">Reset password</a>
  </p>
  <p style="font-size:12px;color:#666">
    Or paste this link into your browser:<br>{safe_url}
  </p>
  <p style="font-size:12px;color:#666">
    If you did not request this, you can safely ignore this email.
    Your password will not change.
  </p>
</div>
""",
        subtype="html",
    )
    _send(msg)


def send_password_changed_email(to_email: str, name: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = "Your password was changed"
    msg["From"] = _sender()
    msg["To"] = to_email
    msg.set_content(
        f"Hi {name or 'there'},\n\n"
        "Your password was just changed. If this was not you, contact support "
        "immediately."
    )
    _send(msg)
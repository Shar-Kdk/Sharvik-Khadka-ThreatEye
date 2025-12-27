"""Email Utilities for Authentication

This module handles sending verification emails to users with HTML formatting.
Uses Django's EmailMultiAlternatives to send both plain text and HTML versions.
"""

from django.core.mail import EmailMultiAlternatives
from django.conf import settings


def send_verification_email(user):
    
    # Use existing code or generate new one
    if not user.verification_code:
        verification_code = user.generate_verification_code()
    else:
        verification_code = user.verification_code
    
    subject = '🔐 ThreatEye - Verify Your Email'
    
    # Plain text version (fallback)
    text_content = f"""
Hello {user.first_name or 'User'},

Welcome to ThreatEye! Your account has been created successfully.

Your email verification code is: {verification_code}

This code will expire in 5 minutes.

If you didn't request this code, please ignore this email.

Best regards,
ThreatEye Security Team
    """
    
    # HTML version (styled)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f4;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f4; padding: 20px 0;">
            <tr>
                <td align="center">
                    <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <!-- Header -->
                        <tr>
                            <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                                <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">
                                    🛡️ ThreatEye
                                </h1>
                                <p style="margin: 10px 0 0 0; color: #e0e7ff; font-size: 14px;">
                                    Intelligent Security Detection System
                                </p>
                            </td>
                        </tr>
                        
                        <!-- Body -->
                        <tr>
                            <td style="padding: 40px 30px;">
                                <h2 style="margin: 0 0 20px 0; color: #1a202c; font-size: 24px; font-weight: 600;">
                                    Welcome, {user.first_name or 'User'}! 👋
                                </h2>
                                
                                <p style="margin: 0 0 20px 0; color: #4a5568; font-size: 16px; line-height: 1.6;">
                                    Your ThreatEye account has been created successfully. To complete your registration, please verify your email address using the code below:
                                </p>
                                
                                <!-- Verification Code Box -->
                                <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                                    <tr>
                                        <td align="center" style="background-color: #f7fafc; border: 2px dashed #667eea; border-radius: 8px; padding: 30px;">
                                            <p style="margin: 0 0 10px 0; color: #718096; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">
                                                Your Verification Code
                                            </p>
                                            <p style="margin: 0; color: #667eea; font-size: 36px; font-weight: 700; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                                                {verification_code}
                                            </p>
                                        </td>
                                    </tr>
                                </table>
                                
                                <div style="background-color: #fff5f5; border-left: 4px solid #f56565; padding: 15px 20px; margin: 20px 0; border-radius: 4px;">
                                    <p style="margin: 0; color: #742a2a; font-size: 14px;">
                                        ⏱️ <strong>Important:</strong> This code will expire in <strong>5 minutes</strong>
                                    </p>
                                </div>
                                
                                <p style="margin: 20px 0 0 0; color: #718096; font-size: 14px; line-height: 1.6;">
                                    If you didn't create a ThreatEye account, please ignore this email or contact our security team if you have concerns.
                                </p>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #1a202c; padding: 30px; text-align: center;">
                                <p style="margin: 0 0 10px 0; color: #a0aec0; font-size: 14px;">
                                    Best regards,<br>
                                    <strong style="color: #e2e8f0;">ThreatEye Security Team</strong>
                                </p>
                                <p style="margin: 15px 0 0 0; color: #718096; font-size: 12px;">
                                    © 2025 ThreatEye. All rights reserved.
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    try:
        # Create email message with both text and HTML versions
        msg = EmailMultiAlternatives(
            subject,
            text_content,  # Plain text fallback
            settings.DEFAULT_FROM_EMAIL,
            [user.email]
        )
        
        # Attach HTML version (preferred by email clients)
        msg.attach_alternative(html_content, "text/html")
        
        # Send email via SMTP (Gmail)
        msg.send()
        return True
        
    except Exception as e:
        # Log error and return False (email sending failed)
        print(f"Error sending email to {user.email}: {str(e)}")
        return False

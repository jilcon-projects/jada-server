import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_email_with_template(to_email, to_name, template_id, params=None):
    """
    Send an email using Brevo API with a template
    
    Args:
        to_email: Recipient email
        to_name: Recipient name
        template_id: Brevo template ID
        params: Dictionary of parameters to pass to the template
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Configure API key authorization
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY
        
        # Create an instance of the API class
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
        
        # Create a template email
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": to_email, "name": to_name}],
            template_id=template_id,
            params=params or {}
        )
        
        # Send the email
        api_response = api_instance.send_transac_email(send_smtp_email)
        logger.info(f"Email sent successfully. Message ID: {api_response.message_id}")
        return True
        
    except ApiException as e:
        logger.error(f"Exception when calling TransactionalEmailsApi->send_transac_email: {e}")
        return False

def send_custom_email(to_email, to_name, subject, html_content, text_content=None):
    """
    Send a custom email using Brevo API without a template
    
    Args:
        to_email: Recipient email
        to_name: Recipient name
        subject: Email subject
        html_content: HTML content of the email
        text_content: Plain text content of the email (optional)
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Configure API key authorization
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY
        
        # Create an instance of the API class
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
        
        # Set up sender
        sender = {"name": settings.DEFAULT_FROM_NAME, "email": settings.DEFAULT_FROM_EMAIL}
        
        # Create a custom email
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": to_email, "name": to_name}],
            html_content=html_content,
            text_content=text_content or '',
            sender=sender,
            subject=subject
        )
        
        # Send the email
        api_response = api_instance.send_transac_email(send_smtp_email)
        logger.info(f"Email sent successfully. Message ID: {api_response.message_id}")
        return True
        
    except ApiException as e:
        logger.error(f"Exception when calling TransactionalEmailsApi->send_transac_email: {e}")
        return False
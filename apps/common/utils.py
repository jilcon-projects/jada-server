# apps/common/utils.py
"""
Common utility functions used across the BuildCalc application
"""

import uuid
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string


def generate_unique_filename(original_filename: str, prefix: str = '') -> str:
    """
    Generate a unique filename with timestamp and UUID
    
    Args:
        original_filename: The original file name
        prefix: Optional prefix for the filename
    
    Returns:
        Unique filename string
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = str(uuid.uuid4())[:8]
    file_extension = original_filename.split('.')[-1] if '.' in original_filename else ''
    
    if prefix:
        return f"{prefix}_{timestamp}_{unique_id}.{file_extension}"
    return f"{timestamp}_{unique_id}.{file_extension}"


def generate_random_string(length: int = 8, include_numbers: bool = True, 
                          include_special: bool = False) -> str:
    """
    Generate a random string of specified length
    
    Args:
        length: Length of the string to generate
        include_numbers: Whether to include numbers
        include_special: Whether to include special characters
    
    Returns:
        Random string
    """
    chars = string.ascii_letters
    if include_numbers:
        chars += string.digits
    if include_special:
        chars += '!@#$%^&*'
    
    return ''.join(secrets.choice(chars) for _ in range(length))


def hash_string(text: str, algorithm: str = 'sha256') -> str:
    """
    Hash a string using the specified algorithm
    
    Args:
        text: String to hash
        algorithm: Hashing algorithm to use
    
    Returns:
        Hashed string
    """
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(text.encode('utf-8'))
    return hash_obj.hexdigest()


def format_currency(amount: Union[int, float, Decimal], 
                   currency_symbol: str = '$') -> str:
    """
    Format a number as currency
    
    Args:
        amount: Amount to format
        currency_symbol: Currency symbol to use
    
    Returns:
        Formatted currency string
    """
    if isinstance(amount, (int, float)):
        amount = Decimal(str(amount))
    
    return f"{currency_symbol}{amount:,.2f}"


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        Formatted file size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def validate_email_format(email: str) -> bool:
    """
    Validate email format using basic regex
    
    Args:
        email: Email string to validate
    
    Returns:
        True if valid, False otherwise
    """
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert a value to integer
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Integer value or default
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Safely convert a value to float
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Float value or default
    """
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_decimal(value: Any, default: Decimal = Decimal('0.00')) -> Decimal:
    """
    Safely convert a value to Decimal
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Decimal value or default
    """
    try:
        return Decimal(str(value))
    except (ValueError, TypeError, Decimal.InvalidOperation):
        return default


def get_client_ip(request) -> str:
    """
    Get client IP address from request
    
    Args:
        request: Django request object
    
    Returns:
        Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip


def send_notification_email(to_email: str, subject: str, template_name: str, 
                          context: Dict[str, Any], from_email: str = None) -> bool:
    """
    Send a notification email using a template
    
    Args:
        to_email: Recipient email
        subject: Email subject
        template_name: Template file name (without extension)
        context: Context for template rendering
        from_email: Sender email (uses default if None)
    
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        html_template = f'emails/{template_name}.html'
        text_template = f'emails/{template_name}.txt'
        
        html_message = render_to_string(html_template, context)
        text_message = render_to_string(text_template, context)
        
        send_mail(
            subject=subject,
            message=text_message,
            from_email=from_email or settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            html_message=html_message,
            fail_silently=False
        )
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def chunks(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Divide a list into chunks of specified size
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
    
    Returns:
        List of chunks
    """
    result = []
    for i in range(0, len(lst), chunk_size):
        result.append(lst[i:i + chunk_size])
    return result


def calculate_percentage(part: Union[int, float, Decimal], 
                       whole: Union[int, float, Decimal]) -> float:
    """
    Calculate percentage of part relative to whole
    
    Args:
        part: Part value
        whole: Whole value
    
    Returns:
        Percentage as float
    """
    if whole == 0:
        return 0.0
    return float(part / whole * 100)


def truncate_string(text: str, max_length: int, suffix: str = '...') -> str:
    """
    Truncate string to maximum length
    
    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def get_file_extension(filename: str) -> str:
    """
    Get file extension from filename
    
    Args:
        filename: File name
    
    Returns:
        File extension (without dot)
    """
    return filename.split('.')[-1].lower() if '.' in filename else ''


def validate_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
    """
    Validate if file has allowed extension
    
    Args:
        filename: File name to validate
        allowed_extensions: List of allowed extensions
    
    Returns:
        True if valid, False otherwise
    """
    extension = get_file_extension(filename)
    return extension in [ext.lower() for ext in allowed_extensions]


def days_between_dates(date1: datetime, date2: datetime) -> int:
    """
    Calculate days between two dates
    
    Args:
        date1: First date
        date2: Second date
    
    Returns:
        Number of days between dates
    """
    return abs((date2 - date1).days)


def is_business_day(date: datetime) -> bool:
    """
    Check if a given date is a business day (Monday to Friday)
    
    Args:
        date: Date to check
    
    Returns:
        True if business day, False otherwise
    """
    return date.weekday() < 5


def get_next_business_day(date: datetime) -> datetime:
    """
    Get the next business day after the given date
    
    Args:
        date: Starting date
    
    Returns:
        Next business day
    """
    next_day = date + timedelta(days=1)
    while not is_business_day(next_day):
        next_day += timedelta(days=1)
    return next_day


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing/replacing invalid characters
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    import re
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove multiple underscores
    sanitized = re.sub(r'_{2,}', '_', sanitized)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    return sanitized or 'file'


def create_api_response(success: bool, message: str, data: Any = None, 
                       errors: Optional[Dict] = None, code: str = '') -> Dict:
    """
    Create standardized API response
    
    Args:
        success: Success status
        message: Response message
        data: Response data
        errors: Error details
        code: Response code
    
    Returns:
        Standardized response dictionary
    """
    response = {
        'success': success,
        'message': message,
        'code': code,
        'data': data if success else None
    }
    
    if not success and errors:
        response['errors'] = errors
    
    return response
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

def custom_exception_handler(exc, context):
    """Custom exception handler for authentication errors"""
    
    response = exception_handler(exc, context)
    
    if response is not None and response.status_code == 401:
        
        error_detail = str(response.data.get('detail', ''))
        
        if 'expired' in error_detail.lower():
            # Token expired
            custom_response_data = {
                'success': False,
                'message': 'Access token has expired',
                'code': 'token_expired',
                'data': None
            }
        elif 'invalid' in error_detail.lower():
            # Invalid token
            custom_response_data = {
                'success': False,
                'message': 'Invalid access token',
                'code': 'token_invalid',
                'data': None
            }
        else:
            # No token provided or other auth error
            custom_response_data = {
                'success': False,
                'message': 'Authentication token required',
                'code': 'token_required',
                'data': None
            }
        
        response.data = custom_response_data
    
    return response
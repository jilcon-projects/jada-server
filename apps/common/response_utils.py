from rest_framework.response import Response
from rest_framework import status
from typing import Any, Optional, Dict, List


class StandardResponseCodes:
    """Standard response codes for consistent API responses"""
    
    # Success codes
    SUCCESS_GENERIC = "success"
    CREATED_SUCCESSFULLY = "created_successfully"
    UPDATED_SUCCESSFULLY = "updated_successfully"
    DELETED_SUCCESSFULLY = "deleted_successfully"
    RETRIEVED_SUCCESSFULLY = "retrieved_successfully"
    
    # Authentication codes
    LOGIN_SUCCESSFUL = "login_successful"
    REGISTRATION_SUCCESSFUL = "registration_successful"
    PASSWORD_RESET_SUCCESSFUL = "password_reset_successful"
    EMAIL_VERIFICATION_SUCCESSFUL = "email_verification_successful"

    ACCOUNT_DEACTIVATED = "account_deactivated"
    EMAIL_NOT_VERIFIED = "email_not_verified"
    INVALID_CREDENTIALS = "invalid_credentials"
    TWO_FA_REQUIRED = "2fa_required"

    # Profile related codes
    PROFILE_COMPLETED_SUCCESSFUL = "profile_completed_successful"
    PROFILE_COMPLETION_FAILED = "profile_completion_failed"
    PROFILE_ALREADY_COMPLETED = "profile_already_completed"

    USER_NOT_FOUND = "user_not_found"
    DEVICE_FORGOTTEN = "device_forgotten"
    DEVICE_NOT_FOUND = "device_not_found"
    REMEMBERED_DEVICES_RETRIEVED = "remembered_devices_retrieved"
    USER_STATUS_RETRIEVED = "user_status_retrieved"
    LOGOUT_SUCCESSFUL = "logout_successful"
    INVALID_TOKEN = "invalid_token"
    INCORRECT_PASSWORD = "incorrect_password"
        
    # Password reset related codes
    PASSWORD_RESET_CONFIRMED = "password_reset_confirmed"
    PASSWORD_RESET_EMAIL_SENT = "password_reset_email_sent"
    PASSWORD_RESET_EMAIL_FAILED = "password_reset_email_failed"
    

    # Password reset OTP codes
    PASSWORD_RESET_OTP_SENT = "password_reset_otp_sent"
    PASSWORD_RESET_OTP_FAILED = "password_reset_otp_failed"
    OTP_VERIFICATION_FAILED = "otp_verification_failed"

    # Profile retrieve/update related codes
    PROFILE_RETRIEVED_SUCCESSFUL = "profile_retrieved_successful"
    PROFILE_UPDATED_SUCCESSFUL = "profile_updated_successful"
    PROFILE_UPDATE_FAILED = "profile_update_failed"

    # Password change related codes
    PASSWORD_CHANGED_SUCCESSFUL = "password_changed_successful"
    PASSWORD_CHANGE_FAILED = "password_change_failed"
    INCORRECT_CURRENT_PASSWORD = "incorrect_current_password"


    # Google Authentication codes
    GOOGLE_SIGNIN_SUCCESSFUL = "google_signin_successful"
    GOOGLE_SIGNUP_SUCCESSFUL = "google_signup_successful"
    GOOGLE_TOKEN_INVALID = "google_token_invalid"
    GOOGLE_AUTH_FAILED = "google_auth_failed"

    # 2FA related codes
    TWO_FA_REQUIRED = "2fa_required"
    TWO_FA_SETUP_INITIATED = "2fa_setup_initiated"
    TWO_FA_ALREADY_ENABLED = "2fa_already_enabled"
    TWO_FA_ENABLED = "2fa_enabled"
    TWO_FA_DISABLED = "2fa_disabled"
    TWO_FA_SETUP_FAILED = "2fa_setup_failed"
    TWO_FA_CONFIRMATION_FAILED = "2fa_confirmation_failed"
    TWO_FA_VERIFICATION_FAILED = "2fa_verification_failed"
    TWO_FA_DISABLE_FAILED = "2fa_disable_failed"
    TWO_FA_NOT_ENABLED = "2fa_not_enabled"
    INVALID_OTP = "invalid_otp"
    INVALID_BACKUP_CODE = "invalid_backup_code"
    BACKUP_CODE_VERIFICATION_FAILED = "backup_code_verification_failed"


    # Project related codes
    PROJECT_CREATED_SUCCESSFUL = "project_created_successful"
    PROJECT_RETRIEVED_SUCCESSFUL = "project_retrieved_successful"
    PROJECT_UPDATED_SUCCESSFUL = "project_updated_successful"
    PROJECT_DELETED_SUCCESSFUL = "project_deleted_successful"
    
    # Plan related codes
    PLAN_UPLOADED_SUCCESSFUL = "plan_uploaded_successful"
    PLAN_RETRIEVED_SUCCESSFUL = "plan_retrieved_successful"
    
    # Takeoff related codes
    TAKEOFF_CREATED_SUCCESSFUL = "takeoff_created_successful"
    TAKEOFF_RETRIEVED_SUCCESSFUL = "takeoff_retrieved_successful"
    TAKEOFF_UPDATED_SUCCESSFUL = "takeoff_updated_successful"
    
    # Error codes
    ERROR_GENERIC = "error"
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    PERMISSION_ERROR = "permission_error"
    NOT_FOUND_ERROR = "not_found_error"
    SERVER_ERROR = "server_error"
    
    # Authentication error codes  
    REGISTRATION_PROCESS_FAILED = "registration_process_failed"
    VERIFICATION_INVALID = "verification_invalid"
    VERIFICATION_TOKEN_INVALID = "verification_token_invalid"
    VERIFICATION_LINK_INVALID = "verification_link_invalid"
    
    # Project error codes
    PROJECT_CREATION_FAILED = "project_creation_failed"
    PROJECT_RETRIEVAL_FAILED = "project_retrieval_failed"
    PROJECT_UPDATE_FAILED = "project_update_failed"
    PROJECT_DELETE_FAILED = "project_delete_failed"
    
    # Plan error codes
    PLAN_UPLOAD_FAILED = "plan_upload_failed"
    PLAN_RETRIEVAL_FAILED = "plan_retrieval_failed"
    INVALID_FILE_FORMAT = "invalid_file_format"
    
    # Takeoff error codes
    TAKEOFF_CREATION_FAILED = "takeoff_creation_failed"
    TAKEOFF_RETRIEVAL_FAILED = "takeoff_retrieval_failed"
    TAKEOFF_UPDATE_FAILED = "takeoff_update_failed"

class StandardResponseMessages:
    """Standard response messages for consistent API responses"""
    
    # Success messages
    SUCCESS_GENERIC = "Operation completed successfully"
    CREATED_SUCCESSFULLY = "Resource created successfully"
    UPDATED_SUCCESSFULLY = "Resource updated successfully"
    DELETED_SUCCESSFULLY = "Resource deleted successfully"
    RETRIEVED_SUCCESSFULLY = "Resource retrieved successfully"
    
    # Authentication messages
    LOGIN_SUCCESSFUL = "Login successful"
    REGISTRATION_SUCCESSFUL = "Registration successful"
    PASSWORD_RESET_SUCCESSFUL = "Password reset successful"
    EMAIL_VERIFICATION_SUCCESSFUL = "Email verification successful"

    ACCOUNT_DEACTIVATED = "Account is deactivated"
    EMAIL_NOT_VERIFIED = "Please verify your email before logging in"
    INVALID_CREDENTIALS = "Invalid credentials"
    TWO_FA_REQUIRED = "2FA verification required"

    # Add to StandardResponseMessages class
    USER_NOT_FOUND = "User not found"
    DEVICE_FORGOTTEN = "Device forgotten successfully"
    DEVICE_NOT_FOUND = "Device not found"
    REMEMBERED_DEVICES_RETRIEVED = "Remembered devices retrieved successfully"
    USER_STATUS_RETRIEVED = "User status retrieved successfully"
    LOGOUT_SUCCESSFUL = "Logged out successfully"
    INVALID_TOKEN = "Invalid token"
    INCORRECT_PASSWORD = "Incorrect password"

    # Profile messages
    PROFILE_COMPLETED_SUCCESSFUL = "Profile completed successfully"
    PROFILE_COMPLETION_FAILED = "Profile completion failed"
    PROFILE_ALREADY_COMPLETED = "Profile is already completed"

    # Password reset messages
    PASSWORD_RESET_EMAIL_SENT = "If the email exists, a password reset link has been sent"
    PASSWORD_RESET_EMAIL_FAILED = "Failed to send password reset email"

    # Password reset confirmation messages
    PASSWORD_RESET_CONFIRMED = "Password reset successful"
    PASSWORD_RESET_FAILED = "Password reset failed"
    PASSWORD_RESET_TOKEN_INVALID = "Invalid or expired reset token"

    # Password reset OTP messages
    PASSWORD_RESET_OTP_SENT = "Password reset code sent to your email"
    PASSWORD_RESET_OTP_FAILED = "Failed to send password reset code"
    OTP_VERIFICATION_FAILED = "Invalid OTP"

    # Profile retrieve/update messages
    PROFILE_RETRIEVED_SUCCESSFUL = "Profile retrieved successfully"
    PROFILE_UPDATED_SUCCESSFUL = "Profile updated successfully"
    PROFILE_UPDATE_FAILED = "Profile update failed"

    # Password change messages
    PASSWORD_CHANGED_SUCCESSFUL = "Password changed successfully"
    PASSWORD_CHANGE_FAILED = "Password change failed"
    INCORRECT_CURRENT_PASSWORD = "Current password is incorrect"


    # Google Authentication messages
    GOOGLE_SIGNIN_SUCCESSFUL = "Signed in with Google successfully"
    GOOGLE_SIGNUP_SUCCESSFUL = "Account created and signed in with Google successfully"
    GOOGLE_TOKEN_INVALID = "Invalid Google token"
    GOOGLE_AUTH_FAILED = "Google authentication failed"


    # 2FA related messages
    TWO_FA_REQUIRED = "2FA verification required"
    TWO_FA_SETUP_INITIATED = "2FA setup initiated"
    TWO_FA_ALREADY_ENABLED = "2FA is already enabled"
    TWO_FA_ENABLED = "2FA enabled successfully"
    TWO_FA_DISABLED = "2FA disabled successfully"
    TWO_FA_SETUP_FAILED = "Failed to set up 2FA"
    TWO_FA_CONFIRMATION_FAILED = "Failed to confirm 2FA"
    TWO_FA_VERIFICATION_FAILED = "Failed to verify 2FA"
    TWO_FA_DISABLE_FAILED = "Failed to disable 2FA"
    TWO_FA_NOT_ENABLED = "2FA is not enabled"
    INVALID_OTP = "Invalid OTP token"
    INVALID_BACKUP_CODE = "Invalid backup code"
    BACKUP_CODE_VERIFICATION_FAILED = "Failed to verify backup code"

    # Project messages
    PROJECT_CREATED_SUCCESSFUL = "Project created successfully"
    PROJECT_RETRIEVED_SUCCESSFUL = "Project(s) retrieved successfully"
    PROJECT_UPDATED_SUCCESSFUL = "Project updated successfully"
    PROJECT_DELETED_SUCCESSFUL = "Project deleted successfully"
    
    
    # Plan messages
    PLAN_UPLOADED_SUCCESSFUL = "Plan uploaded successfully"
    PLAN_RETRIEVED_SUCCESSFUL = "Plan(s) retrieved successfully"
    
    # Takeoff messages
    TAKEOFF_CREATED_SUCCESSFUL = "Takeoff created successfully"
    TAKEOFF_RETRIEVED_SUCCESSFUL = "Takeoff(s) retrieved successfully"
    TAKEOFF_UPDATED_SUCCESSFUL = "Takeoff updated successfully"
    
    # Error messages
    ERROR_GENERIC = "An error occurred"
    VALIDATION_ERROR = "Validation error"
    AUTHENTICATION_ERROR = "Authentication required"
    PERMISSION_ERROR = "Permission denied"
    NOT_FOUND_ERROR = "Resource not found"
    SERVER_ERROR = "Internal server error"
    
    # Project error messages
    PROJECT_CREATION_FAILED = "Project creation failed"
    PROJECT_RETRIEVAL_FAILED = "Project retrieval failed"
    PROJECT_UPDATE_FAILED = "Project update failed"
    PROJECT_DELETE_FAILED = "Project deletion failed"
    
    # Plan error messages
    PLAN_UPLOAD_FAILED = "Plan upload failed"
    PLAN_RETRIEVAL_FAILED = "Plan retrieval failed"
    INVALID_FILE_FORMAT = "Invalid file format. Only PDF files are allowed"
    
    # Takeoff error messages
    TAKEOFF_CREATION_FAILED = "Takeoff creation failed"
    TAKEOFF_RETRIEVAL_FAILED = "Takeoff retrieval failed"
    TAKEOFF_UPDATE_FAILED = "Takeoff update failed"


def create_response_data(
    success: bool,
    message: str,
    response_code: str,
    data: Any = None,
    errors: Optional[Dict] = None
) -> Dict:
    """
    Create a standardized response dictionary following the specified format
    
    Args:
        success: Boolean indicating if the operation was successful
        message: Human-readable message describing the result
        response_code: Unique code for the response
        data: The actual data to return (can be dict, list, or None)
        errors: Error details if any
    
    Returns:
        Dictionary in the standard response format
    """
    response_data = {
        "success": success,
        "message": message,
        "code": response_code,
        "data": data if data is not None else [] if success else None
    }
    
    if errors and not success:
        response_data["errors"] = errors
    
    return response_data


def success_response(
    data: Any = None,
    message: str = StandardResponseMessages.SUCCESS_GENERIC,
    response_code: str = StandardResponseCodes.SUCCESS_GENERIC,
    status_code: int = status.HTTP_200_OK
) -> Response:
    """
    Create a success response
    
    Args:
        data: The data to return
        message: Success message
        response_code: Response code
        status_code: HTTP status code
    
    Returns:
        DRF Response object
    """
    response_data = create_response_data(
        success=True,
        message=message,
        response_code=response_code,
        data=data
    )
    
    return Response(response_data, status=status_code)


def error_response(
    message: str = StandardResponseMessages.ERROR_GENERIC,
    response_code: str = StandardResponseCodes.ERROR_GENERIC,
    status_code: int = status.HTTP_400_BAD_REQUEST,
    errors: Optional[Dict] = None
) -> Response:
    """
    Create an error response
    
    Args:
        message: Error message
        response_code: Response code
        status_code: HTTP status code
        errors: Error details
    
    Returns:
        DRF Response object
    """
    response_data = create_response_data(
        success=False,
        message=message,
        response_code=response_code,
        data=None,
        errors=errors
    )
    
    return Response(response_data, status=status_code)


def created_response(
    data: Any = None,
    message: str = StandardResponseMessages.CREATED_SUCCESSFULLY,
    response_code: str = StandardResponseCodes.CREATED_SUCCESSFULLY
) -> Response:
    """Create a response for successful creation"""
    return success_response(
        data=data,
        message=message,
        response_code=response_code,
        status_code=status.HTTP_201_CREATED
    )


def not_found_response(
    message: str = StandardResponseMessages.NOT_FOUND_ERROR,
    response_code: str = StandardResponseCodes.NOT_FOUND_ERROR
) -> Response:
    """Create a 404 not found response"""
    return error_response(
        message=message,
        response_code=response_code,
        status_code=status.HTTP_404_NOT_FOUND
    )


def validation_error_response(
    errors: Dict,
    message: str = StandardResponseMessages.VALIDATION_ERROR,
    response_code: str = StandardResponseCodes.VALIDATION_ERROR
) -> Response:
    """Create a validation error response"""
    return error_response(
        message=message,
        response_code=response_code,
        status_code=status.HTTP_400_BAD_REQUEST,
        errors=errors
    )


def server_error_response(
    message: str = StandardResponseMessages.SERVER_ERROR,
    response_code: str = StandardResponseCodes.SERVER_ERROR
) -> Response:
    """Create a server error response"""
    return error_response(
        message=message,
        response_code=response_code,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def permission_denied_response(
    message: str = StandardResponseMessages.PERMISSION_ERROR,
    response_code: str = StandardResponseCodes.PERMISSION_ERROR
) -> Response:
    """Create a permission denied response"""
    return error_response(
        message=message,
        response_code=response_code,
        status_code=status.HTTP_403_FORBIDDEN
    )


def authentication_error_response(
    message: str = StandardResponseMessages.AUTHENTICATION_ERROR,
    response_code: str = StandardResponseCodes.AUTHENTICATION_ERROR
) -> Response:
    """Create an authentication error response"""
    return error_response(
        message=message,
        response_code=response_code,
        status_code=status.HTTP_401_UNAUTHORIZED
    )
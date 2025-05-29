from .response_utils import (
    StandardResponseMessages, 
    StandardResponseCodes,
    success_response,
    error_response,
    created_response,
    validation_error_response,
    authentication_error_response,
)


class ServiceResponse:
    """Universal service response class for all services"""
    def __init__(self, success: bool, message: str, code: str, data=None, errors=None):
        self.success = success
        self.message = message
        self.code = code
        self.data = data
        self.errors = errors
    
    def to_response(self):
        """Convert to HTTP response - handles all conditional logic automatically"""
        if self.success:
            # Success responses
            if 'REGISTRATION' in self.code or 'CREATED' in self.code:
                return created_response(
                    data=self.data,
                    message=self.message,
                    response_code=self.code
                )
            return success_response(
                data=self.data,
                message=self.message,
                response_code=self.code
            )
        
        if self.code == StandardResponseCodes.VALIDATION_ERROR:
            return validation_error_response(
                errors=self.errors or {},
                message=self.message,
                response_code=self.code
            )
        
        if self.code in [StandardResponseCodes.AUTHENTICATION_ERROR, StandardResponseCodes.INVALID_CREDENTIALS]:
            return authentication_error_response(
                message=self.message,
                response_code=self.code
            )
        
        return error_response(
            message=self.message,
            response_code=self.code
        )


class ResponseBuilder:
    
    @staticmethod
    def success(response_type: str, data=None):
        """Build success response using existing constants from response_utils.py"""
        
        type_mapping = {
            # Auth responses
            'registration': (StandardResponseMessages.REGISTRATION_SUCCESSFUL, StandardResponseCodes.REGISTRATION_SUCCESSFUL),
            'login': (StandardResponseMessages.LOGIN_SUCCESSFUL, StandardResponseCodes.LOGIN_SUCCESSFUL),
            'google_signin': (StandardResponseMessages.GOOGLE_SIGNIN_SUCCESSFUL, StandardResponseCodes.GOOGLE_SIGNIN_SUCCESSFUL),
            'google_signup': (StandardResponseMessages.GOOGLE_SIGNUP_SUCCESSFUL, StandardResponseCodes.GOOGLE_SIGNUP_SUCCESSFUL),
            'email_verification': (StandardResponseMessages.EMAIL_VERIFICATION_SUCCESSFUL, StandardResponseCodes.EMAIL_VERIFICATION_SUCCESSFUL),
            'profile_completed': (StandardResponseMessages.PROFILE_COMPLETED_SUCCESSFUL, StandardResponseCodes.PROFILE_COMPLETED_SUCCESSFUL),
            'profile_retrieved': (StandardResponseMessages.PROFILE_RETRIEVED_SUCCESSFUL, StandardResponseCodes.PROFILE_RETRIEVED_SUCCESSFUL),
            'profile_updated': (StandardResponseMessages.PROFILE_UPDATED_SUCCESSFUL, StandardResponseCodes.PROFILE_UPDATED_SUCCESSFUL),
            'password_reset_otp_sent': (StandardResponseMessages.PASSWORD_RESET_OTP_SENT, StandardResponseCodes.PASSWORD_RESET_OTP_SENT),
            'password_reset_confirmed': (StandardResponseMessages.PASSWORD_RESET_CONFIRMED, StandardResponseCodes.PASSWORD_RESET_CONFIRMED),
            'password_changed': (StandardResponseMessages.PASSWORD_CHANGED_SUCCESSFUL, StandardResponseCodes.PASSWORD_CHANGED_SUCCESSFUL),
            '2fa_setup': (StandardResponseMessages.TWO_FA_SETUP_INITIATED, StandardResponseCodes.TWO_FA_SETUP_INITIATED),
            '2fa_enabled': (StandardResponseMessages.TWO_FA_ENABLED, StandardResponseCodes.TWO_FA_ENABLED),
            '2fa_disabled': (StandardResponseMessages.TWO_FA_DISABLED, StandardResponseCodes.TWO_FA_DISABLED),
            'user_status': (StandardResponseMessages.USER_STATUS_RETRIEVED, StandardResponseCodes.USER_STATUS_RETRIEVED),
            'device_forgotten': (StandardResponseMessages.DEVICE_FORGOTTEN, StandardResponseCodes.DEVICE_FORGOTTEN),
            'devices_retrieved': (StandardResponseMessages.REMEMBERED_DEVICES_RETRIEVED, StandardResponseCodes.REMEMBERED_DEVICES_RETRIEVED),
            'logout': (StandardResponseMessages.LOGOUT_SUCCESSFUL, StandardResponseCodes.LOGOUT_SUCCESSFUL),
        }
        
        message, code = type_mapping.get(response_type, 
            (StandardResponseMessages.SUCCESS_GENERIC, StandardResponseCodes.SUCCESS_GENERIC))
        
        return ServiceResponse(
            success=True,
            message=message,
            code=code,
            data=data
        )
    
    @staticmethod
    def error(response_type: str, errors=None):
        """Build error response using existing constants from response_utils.py"""
        
        type_mapping = {
            # Auth errors
            'validation': (StandardResponseMessages.VALIDATION_ERROR, StandardResponseCodes.VALIDATION_ERROR),
            'authentication': (StandardResponseMessages.AUTHENTICATION_ERROR, StandardResponseCodes.AUTHENTICATION_ERROR),
            'invalid_credentials': (StandardResponseMessages.INVALID_CREDENTIALS, StandardResponseCodes.INVALID_CREDENTIALS),
            'account_deactivated': (StandardResponseMessages.ACCOUNT_DEACTIVATED, StandardResponseCodes.ACCOUNT_DEACTIVATED),
            'email_not_verified': (StandardResponseMessages.EMAIL_NOT_VERIFIED, StandardResponseCodes.EMAIL_NOT_VERIFIED),
            'registration_failed': ("Registration process failed", StandardResponseCodes.REGISTRATION_PROCESS_FAILED),
            'verification_invalid': ("Invalid verification link. Token or UID missing.", StandardResponseCodes.VERIFICATION_INVALID),
            'verification_token_invalid': ("Invalid or expired verification link.", StandardResponseCodes.VERIFICATION_TOKEN_INVALID),
            'verification_link_invalid': ("Invalid verification link.", StandardResponseCodes.VERIFICATION_LINK_INVALID),
            'profile_completion_failed': (StandardResponseMessages.PROFILE_COMPLETION_FAILED, StandardResponseCodes.PROFILE_COMPLETION_FAILED),
            'profile_already_completed': (StandardResponseMessages.PROFILE_ALREADY_COMPLETED, StandardResponseCodes.PROFILE_ALREADY_COMPLETED),
            'password_reset_otp_failed': ("Failed to send password reset code", StandardResponseCodes.PASSWORD_RESET_OTP_FAILED),
            'otp_verification_failed': ("Invalid email or OTP", StandardResponseCodes.OTP_VERIFICATION_FAILED),
            'profile_update_failed': (StandardResponseMessages.PROFILE_UPDATE_FAILED, StandardResponseCodes.PROFILE_UPDATE_FAILED),
            'password_change_failed': (StandardResponseMessages.PASSWORD_CHANGE_FAILED, StandardResponseCodes.PASSWORD_CHANGE_FAILED),
            'incorrect_current_password': (StandardResponseMessages.INCORRECT_CURRENT_PASSWORD, StandardResponseCodes.INCORRECT_CURRENT_PASSWORD),
            '2fa_already_enabled': (StandardResponseMessages.TWO_FA_ALREADY_ENABLED, StandardResponseCodes.TWO_FA_ALREADY_ENABLED),
            '2fa_setup_failed': (StandardResponseMessages.TWO_FA_SETUP_FAILED, StandardResponseCodes.TWO_FA_SETUP_FAILED),
            '2fa_confirmation_failed': (StandardResponseMessages.TWO_FA_CONFIRMATION_FAILED, StandardResponseCodes.TWO_FA_CONFIRMATION_FAILED),
            'invalid_otp': (StandardResponseMessages.INVALID_OTP, StandardResponseCodes.INVALID_OTP),
            '2fa_verification_failed': (StandardResponseMessages.TWO_FA_VERIFICATION_FAILED, StandardResponseCodes.TWO_FA_VERIFICATION_FAILED),
            'user_not_found': (StandardResponseMessages.USER_NOT_FOUND, StandardResponseCodes.USER_NOT_FOUND),
            'incorrect_password': (StandardResponseMessages.INCORRECT_PASSWORD, StandardResponseCodes.INCORRECT_PASSWORD),
            '2fa_not_enabled': (StandardResponseMessages.TWO_FA_NOT_ENABLED, StandardResponseCodes.TWO_FA_NOT_ENABLED),
            '2fa_disable_failed': (StandardResponseMessages.TWO_FA_DISABLE_FAILED, StandardResponseCodes.TWO_FA_DISABLE_FAILED),
            'device_not_found': (StandardResponseMessages.DEVICE_NOT_FOUND, StandardResponseCodes.DEVICE_NOT_FOUND),
            'invalid_token': (StandardResponseMessages.INVALID_TOKEN, StandardResponseCodes.INVALID_TOKEN),
            'google_token_invalid': (StandardResponseMessages.GOOGLE_TOKEN_INVALID, StandardResponseCodes.GOOGLE_TOKEN_INVALID),
            'google_auth_failed': (StandardResponseMessages.GOOGLE_AUTH_FAILED, StandardResponseCodes.GOOGLE_AUTH_FAILED),
            
        }
        
        message, code = type_mapping.get(response_type, 
            (StandardResponseMessages.ERROR_GENERIC, StandardResponseCodes.ERROR_GENERIC))
        
        return ServiceResponse(
            success=False,
            message=message,
            code=code,
            errors=errors
        )
    
    @staticmethod
    def custom_response(success: bool, message: str, code: str, data=None, errors=None):
        """Custom response when standard types don't fit exactly"""
        return ServiceResponse(
            success=success,
            message=message,
            code=code,
            data=data,
            errors=errors
        )
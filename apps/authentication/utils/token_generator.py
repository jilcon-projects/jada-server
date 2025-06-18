import hashlib
import time
from django.conf import settings
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import base36_to_int, int_to_base36


class CustomTokenGenerator:
    """
    Custom token generator with configurable expiration time.
    Default expiration: 15 minutes (900 seconds)
    """
    
    def __init__(self, timeout=900):  
        self.timeout = timeout
    
    def make_token(self, user):
        """
        Return a token that can be used once to verify email for the given user.
        """
        return self._make_token_with_timestamp(user, self._num_seconds(self._now()))
    
    def check_token(self, user, token):
        """
        Check that an email verification token is correct for a given user.
        """
        if not (user and token):
            return False
        
        # Parse the token
        try:
            ts_b36, _ = token.split("-", 1)
        except ValueError:
            return False
        
        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False
        
        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False
        
        # Check the timestamp is within limit
        if (self._num_seconds(self._now()) - ts) > self.timeout:
            return False
        
        return True
    
    def _make_token_with_timestamp(self, user, timestamp):
        """
        Create a token with a timestamp.
        """
        ts_b36 = int_to_base36(timestamp)
        hash_string = salted_hmac(
            self.__class__.__name__,
            self._make_hash_value(user, timestamp),
            secret=settings.SECRET_KEY,
            algorithm='sha256',
        ).hexdigest()[::2]
        return f"{ts_b36}-{hash_string}"
    
    def _make_hash_value(self, user, timestamp):
        """
        Create a hash value for the token.
        """
        return f"{user.pk}{user.email}{timestamp}{user.is_email_verified}"
    
    def _num_seconds(self, dt):
        """
        Convert datetime to seconds since epoch.
        """
        return int(time.mktime(dt.timetuple()))
    
    def _now(self):
        """
        Return current datetime.
        """
        from django.utils import timezone
        return timezone.now()


# Create an instance with 15-minute expiration
email_verification_token_generator = CustomTokenGenerator(timeout=900)
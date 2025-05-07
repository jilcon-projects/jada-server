from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from datetime import datetime, timezone, timedelta
from jwt.exceptions import DecodeError
from config.cache import AuthToken
from google.oauth2 import id_token
from config import config
from flask import request
import logging
import base64
import jwt


AUTH_TOKEN_DURATION = config.AUTH_TOKEN_DURATION
AUTH_SECRET_KEY = config.AUTH_SECRET_KEY

class Auth(object):
  @staticmethod
  def get_token_expiration_time(decoded_token):
    expiration_time = decoded_token.get('exp', 0)
    issued_time = decoded_token.get('iat', 0)

    return max(0, expiration_time - issued_time)
  

  @staticmethod
  def verify_token(token, request):
    if token is None:
      return token
    
    try:
      decoded_token = id_token.verify_token(token, request)
      exp = Auth.get_token_expiration_time(decoded_token)
      user_email = decoded_token['email']

      user_key = Auth.create_user_key(user_email)
      AuthToken.set(user_key, token, ex=exp)

      return decoded_token, user_key
    except ValueError as e:
      logging.error(f'Token verification error: {e}')
      return None, None
  

  @staticmethod
  def create_user_key(user_email):
    cipher = Cipher(algorithms.AES(AUTH_SECRET_KEY), modes.ECB(), backend=default_backend())
    padder = padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()

    padded_data = padder.update(user_email.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(encrypted).decode()
  

  @staticmethod
  def validate_user_key(user_key):
    user = None

    try:
      token = AuthToken.get(user_key)
      
      user = jwt.decode(token, options={
        'verify_signature': False
      })
    except DecodeError:
      logging.error(f'Invalid user key provided.')
    except ValueError:
      logging.error(f'Auth user not found.')
    except Exception as e:
      logging.error(f'Token validation error.: {e}')
    
    return user
  

  @staticmethod
  def decrypt_user_key(user_key):
    cipher = Cipher(algorithms.AES(AUTH_SECRET_KEY), modes.ECB(), backend=default_backend())
    unpadder = padding.PKCS7(128).unpadder()
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(base64.b64decode(user_key)) + decryptor.finalize()
    unpadded = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded.decode()
  

  def create_token(user):
    exp = int((datetime.now(timezone.utc) + timedelta(seconds=AUTH_TOKEN_DURATION)).timestamp())
    iat = int(datetime.now(timezone.utc).timestamp())
    email = user['email']

    payload = {
      'email_verified': user['email_verified'],
      'picture': user['picture'],
      'iss': request.host_url,
      'name': user['name'],
      'sub': user['id'],
      'email': email,
      'iat': iat,
      'exp': exp
    }

    token = jwt.encode(payload, config.AUTH_SECRET_KEY, algorithm='HS256')
    user_key = Auth.create_user_key(email)

    AuthToken.set(user_key, token, ex=AUTH_TOKEN_DURATION)

    return payload, user_key
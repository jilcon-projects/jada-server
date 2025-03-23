from datetime import datetime, timezone, timedelta
from jwt.exceptions import DecodeError
from config.cache import AuthToken
from google.oauth2 import id_token
from Crypto.Cipher import AES
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
    cipher = AES.new(AUTH_SECRET_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(Auth.pad(user_email).encode())
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
    cipher = AES.new(AUTH_SECRET_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(user_key)).decode()
    return decrypted.rstrip('\x00')
  

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
  

  @staticmethod
  def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)
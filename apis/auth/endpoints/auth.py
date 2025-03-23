from google.auth.transport import requests
from resources.auth import AuthResource
from utils.response import ApiResponse
from schemas.auth import login_model
from utils.auth import Auth
from ...auth import router
from flask import abort


REQUEST = requests.Request()

@router.route('/social/<path:token>')
class Social(AuthResource):
  @router.marshal_with(login_model)
  def post(self, token):
    decoded_token, user_key = Auth.verify_token(token, REQUEST)
    
    if not decoded_token:
      abort(400, description='Oops! Unable to authorize user. Please refresh the page and try again')
    
    decoded_token['auth_provider'] = decoded_token['iss']

    auth = {
      'profile': decoded_token,
      'token': {
        'refresh_token': user_key,
        'access_token': user_key
      }
    }
    
    return ApiResponse.ok(
      message='Login successful.',
      data=auth
    )


@router.route('/login')
class Credentials(AuthResource):
  @router.marshal_with(login_model)
  def post(self):
    password = self.api.payload.get('password', None)
    email = self.api.payload.get('email', None)

    user = {
      'picture': 'https://lh3.googleusercontent.com/a/...',
      'id': 106242941385741328721,
      'email_verified': True,
      'name': 'John Doe',
      'email': email
    }

    if not user:
      abort(400, description='Oops! Unable to authorize user.')
    
    payload, user_key = Auth.create_token(user)
    
    auth = {
      'profile': payload,
      'token': {
        'refresh_token': user_key,
        'access_token': user_key
      }
    }

    return ApiResponse.ok(
      message='Login successful.',
      data=auth
    )
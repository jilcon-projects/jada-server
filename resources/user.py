from middlewares import auth_token_required
from flask_restx import Resource

class UserResource(Resource):
  method_decorators = [
    auth_token_required
  ]
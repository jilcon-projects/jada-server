from utils.response import ApiResponse
from apis.user import router as user
from apis.auth import router as auth
from utils.app import create_app
from flask_cors import CORS
from config import config


BLUEPRINTS = [
  (user.app, '/api/v1/users'),
  (auth.app, '/api/v1/auth'),
]


# Create and get flask app instance
app, handle_user_exception, handle_exception = create_app(name='API', config=vars(config))


# CORS setup
CORS(app=app, origins=config.CORS_ORIGIN, supports_credentials=True)


# Register blueprints
for blueprint, prefix in BLUEPRINTS:
  app.register_blueprint(blueprint, url_prefix=prefix)


# Flask_restx has been initialized in Blueprint's import therefore,
# re-assign error handling control from flask_restx to flask
app.handle_user_exception = handle_user_exception
app.handle_exception = handle_exception
app.url_map.strict_slashes = False


# Access control setup
@app.after_request
def after_request(response):
  response.headers.add(
    'Access-Control-Allow-Headers',
    'Content-Type,Authentication,True'
  )
    
  response.headers.add(
    'Access-Control-Allow-Methods',
    'GET,PUT,POST,DELETE,OPTIONS'
  )

  return response


# API service status pinger
@app.route('/api/ping', methods=['GET'])
def ping():
  return ApiResponse.ok(message='Server is running OK!')


# Error handlers for all expected errors
@app.errorhandler(422)
def unprocessable(error):
  return ApiResponse.unprocessable(data=error.description)


@app.errorhandler(405)
def not_allowed(error):
  return ApiResponse.not_allowed(data=error.description)


@app.errorhandler(404)
def not_found(error):
  return ApiResponse.not_found(data=error.description)


@app.errorhandler(400)
def bad_request(error):
  return ApiResponse.bad_request(data=error.description)


@app.errorhandler(401)
def unauthorized(error):
  return ApiResponse.unauthorized(data=error.description)


@app.errorhandler(403)
def forbidden(error):
  return ApiResponse.forbidden(data=error.description)


@app.errorhandler(500)
def server_error(error):
  return ApiResponse.server_error(data=error.description)
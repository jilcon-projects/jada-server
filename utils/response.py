class ApiResponse():
  # SECCESS RESPONSES
  def created(message='Resource created successful', data={}):
    return {
      'message': message,
      'success': True,
      'data': data
    }, 201
  
  def ok(message='Request successful', data={}):
    return {
      'message': message,
      'success': True,
      'data': data
    }, 200
  

  # HTTP EXCEPTIONS
  def unprocessable(data={}):
    return {
      'message': 'Unprocessable entity',
      'success': False,
      'data': data
    }, 422
  
  def server_error(data={}):
    return {
      'message': 'Internal server error',
      'success': False,
      'data': data
    }, 500
  
  def unauthorized(data={}):
    return {
      'message': 'Unauthorized',
      'success': False,
      'data': data
    }, 401
  
  def not_allowed(data={}):
    return {
      'message': 'Method not allowed',
      'success': False,
      'data': data
    }, 405

  def bad_request(data={}):
    return {
      'message': 'Bad request',
      'success': False,
      'data': data
    }, 400
  
  def not_found(data={}):
    return {
      'message': 'Resource not found',
      'success': False,
      'data': data
    }, 404

  def forbidden(data={}):
    return {
      'message': 'Forbidden',
      'success': False,
      'data': data
    }, 403
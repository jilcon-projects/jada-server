from config.common import IS_DEVELOPMENT, IS_PRODUCTION
from werkzeug.exceptions import HTTPException
from flask import Flask, Response, g
import traceback
import logging


def log_request(response: Response) -> Response:
  if IS_DEVELOPMENT:
    return response
  
  log_level = g.get('log_level', 0)
  if log_level < logging.WARNING:
    return response

  status = getattr(response, 'status_code', 500)

  request_logger = logging.getLogger('request')
  request_logger.log(log_level, '', extra={
    'status': status
  })

  if g.get('exception_message', None):
    error_logger = logging.getLogger('errorReporter')
    error_logger.log(log_level, '', extra={
      'status': status
    })

  return response


def handle_exception(exception):
  if IS_DEVELOPMENT:
    raise exception
  
  logging.exception(exception)
  message = traceback.format_exc()
  g.exception_message = message
  
  if isinstance(exception, HTTPException):
    description = exception.description
    name = exception.name
    code = exception.code

    if IS_PRODUCTION:
      data = description if type(description) in [list, dict] else {}
    else:
      data = { 'exception': str(exception) }

    return {
      'success': False,
      'message': name,
      'data': data
    }, code

  data = {
    'error': str(exception) if IS_DEVELOPMENT else 'Application Error'
  }
  
  return {
    'message': 'Internal Server Error',
    'success': False,
    'data': data
  }, 500


def configure_app_logger():
  if IS_DEVELOPMENT:
    logging.basicConfig(level=logging.DEBUG)


class AppLogger():
  def __init__(self, app: Flask):
    self.after_request(app)
    self.errorhandler(app)

  def errorhandler(self, app: Flask):
    app.errorhandler(Exception)(handle_exception)

  def after_request(self, app: Flask):
    app.after_request(log_request)
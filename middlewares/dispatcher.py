from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wsgi import peek_path_info
from flask import Flask
import logging


class AppDispatcher(DispatcherMiddleware):
  def __call__(self, environ, start_response):
    request_path = environ.get('PATH_INFO', '')
    prefix = peek_path_info(environ)
    app: Flask = self.mounts.get(f'/{prefix}', self.app)
    logging.info(f'The {app.import_name} app is responding to --> {request_path} \n\n')
    return app(environ, start_response)
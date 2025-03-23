from utils.logger import AppLogger
from flask_caching import Cache
from config.common import CACHE
from flask import Flask


def ndb_wsgi_middleware(wsgi_app):
  def middleware(environ, start_response):
    # TODO: Configure global Cache here
    
    return wsgi_app(environ, start_response)
  
  return middleware


def create_service(app: Flask):
  app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)
  cache = Cache(config=CACHE)
  cache.init_app(app)
  AppLogger(app)
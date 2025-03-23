from flask import Flask

# Create flask app
def create_app(name=__name__, config={}):
  app = Flask(name)
  
  # Update app's configuration
  app.config.update(config)
  
  # There is a bug in flask_restx package that overrides error handling from flask after initialization.
  # The line below extracts flask exception handlers for re-assignment after initializing flask_restx.
  handle_user_exception = app.handle_user_exception
  handle_exception = app.handle_exception

  return app, handle_user_exception, handle_exception
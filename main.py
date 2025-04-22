from middlewares import create_service, AppDispatcher
from utils.logger import configure_app_logger
from werkzeug.serving import run_simple
from config.common import PORT


configure_app_logger()

from apis.main import app as apis

apps = [apis]

for app in apps:
  create_service(app)

app = AppDispatcher('/', {
  '/api': apis
})

if __name__ == '__main__':
  run_simple(
    reloader_type='stat',
    hostname='0.0.0.0',
    use_reloader=True,
    use_debugger=True,
    application=app,
    port=8080
  )
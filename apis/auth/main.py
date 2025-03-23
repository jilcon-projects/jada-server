from flask_restx import Api
from flask import Blueprint

app = Blueprint('auth', __name__)

auth = {
  'apiKey': {
    'name': 'X-JADA-AUTH',
    'type': 'apiKey',
    'in': 'header',
  }
}

router = Api(
  auhorizations=auth,
  security='apiKey',
  doc='/api-docs',
  app=app
)
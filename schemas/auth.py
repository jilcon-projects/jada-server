from schemas import get_default_response_schema
from apis.auth.main import router
from flask_restx import fields

response_model = get_default_response_schema(router)

login_model = router.inherit('Login', response_model, {
  'data': fields.Nested({})
})
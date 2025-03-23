from schemas import get_default_response_schema
from apis.user.main import router
from flask_restx import fields


response_model = get_default_response_schema(router)

users_model = router.inherit('Users Model', response_model, {
  'data': fields.Nested({})
})
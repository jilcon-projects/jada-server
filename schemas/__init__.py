from flask_restx import fields

response_schema = {
  'message': fields.String(
    default='Your request was not successful.',
    description='Response message.'
  ),
  'success': fields.Boolean(
    description='Request completion status.',
    default=False
  ),
  'data': fields.Raw(
    description='Response data envelope.',
    default={}
  )
}

def get_default_response_schema(router):
  return router.model('Response', response_schema)
from flask import request, abort, g
from utils.auth import Auth
from functools import wraps
import logging


def auth_token_required(func):
	@wraps(func)
	def middleware(*args, **kwargs):
		user_key = request.headers.get('X-JADA-AUTH')
		
		if not user_key:
			logging.warning('User key not supplied.')
			abort(401, description='Access denied')
		
		user = Auth.validate_user_key(user_key)

		if not user:
			abort(401, description='Access denied')
		
		g.user = user
		
		return func(*args, **kwargs)

	return middleware
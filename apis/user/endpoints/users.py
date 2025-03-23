from resources.user import UserResource
from utils.response import ApiResponse
from schemas.user import users_model
from ...user import router
from flask import g


@router.route('/list')
class Users(UserResource):
  @router.marshal_with(users_model)
  def get(self):
    user = g.user

    users = [user]

    return ApiResponse.ok(
      message='Users retrieved successfully.',
      data=users
    )
from flask import Flask, session, request, jsonify, g
from app import app, db, jwt
from app.models import User
from flask_jwt_extended import create_access_token, get_jwt, set_access_cookies, \
    unset_jwt_cookies, create_refresh_token, set_refresh_cookies, current_user
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from werkzeug.security import check_password_hash, generate_password_hash
from app.errors import bad_request, error_response
from app.appmessages import AppMessages


# This function is used to get the identity of the user
@jwt.user_identity_loader
def user_identity_lookup(user):
    """
    Function to get the identity of the user.
    :param user: The user object
    :return: The email of the user
    """
    return user.email


# This function is used to get the user object from the JWT token
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """
    Function to get the user object from the JWT token.
    :param _jwt_header: The JWT header
    :param jwt_data: The JWT data
    :return: The user object or None
    """
    identity = jwt_data["sub"]
    return User.query.filter_by(email=identity, deleted_at=None).one_or_none()


# This function is executed before each request
@app.before_request
def before_request():
    """
    Function to execute before each request.
    It checks if the user is authorized and sets the client_id in the global object.
    """
    exclude_path_list = ['/status', '/login',
                         '/register', '/forgot-password', '/reset-password', '/register-organization']
    if request.path not in exclude_path_list:
        request_domain = request.host.lower()
        if request_domain == 'admin.myquantum.com':
            user_id = session.get('user_id')
            if not user_id:
                return error_response(401, AppMessages.UserUnauthorized)
            user = User.query.filter_by(id=user_id).first()
            if not user:
                return error_response(404, AppMessages.UserNotFound)
        else:
            user = User.query.filter_by(domain=request_domain).first()
            if not user:
                return error_response(404, AppMessages.UserNotFound)

        g.client_id = str(user.id)


# This function is executed after each request
@app.after_request
def middleware_for_response(response):
    """
    Function to execute after each request.
    It adds the 'Access-Control-Allow-Credentials' header to the response.
    :param response: The response object
    :return: The response object with the added header
    """
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


# This function is executed when the JWT token has expired
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    """
    Function to execute when the JWT token has expired.
    :param jwt_header: The JWT header
    :param jwt_payload: The JWT payload
    :return: An error response with a 401 status code
    """
    return error_response(401, AppMessages.ExpiredToken)


# This function is executed when the JWT token is invalid
@jwt.invalid_token_loader
def invalid_token_callback(token):
    """
    Function to execute when the JWT token is invalid.
    :param token: The JWT token
    :return: An error response with a 401 status code
    """
    return error_response(401, AppMessages.InvalidToken)


# This function is executed when the JWT token is unauthorized
@jwt.unauthorized_loader
def unauthorized_token_callback(token):
    """
    Function to execute when the JWT token is unauthorized.
    :param token: The JWT token
    :return: An error response with a 401 status code
    """
    return error_response(401, AppMessages.UnauthorizedToken)


# This route is used to refresh the JWT token
@app.route("/refresh_token", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token_func():
    """
    Route to refresh the JWT token.
    It requires a valid refresh token.
    :return: A response with the new access token
    """
    identity = get_jwt_identity()
    user = User.query.filter_by(email=identity, deleted_at=None).first()
    access_token = create_access_token(identity=user, fresh=False)
    response = jsonify({'message': 'refreshed'})
    set_access_cookies(response, access_token)
    return response


# This route is used to display a welcome message
@app.route('/', methods=['GET'])
@jwt_required()
def home():
    """
    Route to display a welcome message.
    :return: A string with the message 'Hello World'
    """
    return "Hello World"


# This route is used to login the user
@app.route('/login', methods=['POST'])
def login():
    """
    Route to login the user.
    It requires the email and password of the user.
    :return: A string with the message 'Login' or an error response
    """
    data = request.get_json() or {}
    if 'email' not in data:
        return bad_request(AppMessages.EmailRequired)
    if "password" not in data:
        return bad_request(AppMessages.PasswordRequired)
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email=email).first()
    if not user:
        return bad_request(AppMessages.UserNotFound)
    g.client_id = str(user.id)
    if not user or not check_password_hash(user.password_hash, password):
        return error_response(400, AppMessages.EmailOrPasswordInvalid)
    access_token = create_access_token(identity=user)
    refresh_token = create_refresh_token(identity=user)
    return "Login"

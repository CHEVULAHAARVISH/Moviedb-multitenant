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


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.email


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(email=identity, deleted_at=None).one_or_none()


@app.before_request
def before_request():
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


@app.after_request
def middleware_for_response(response):
    # Allowing the credentials in the response.
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return error_response(401, AppMessages.ExpiredToken)


@jwt.invalid_token_loader
def invalid_token_callback(token):
    return error_response(401, AppMessages.InvalidToken)


@jwt.unauthorized_loader
def unauthorized_token_callback(token):
    return error_response(401, AppMessages.UnauthorizedToken)


@app.route("/refresh_token", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token_func():
    identity = get_jwt_identity()
    user = User.query.filter_by(email=identity, deleted_at=None).first()
    access_token = create_access_token(identity=user, fresh=False)
    response = jsonify({'message': 'refreshed'})
    set_access_cookies(response, access_token)
    return response


@app.route('/', methods=['GET'])
def home():
    return "Hello World"


@app.route('/login', methods=['POST'])
def login():
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

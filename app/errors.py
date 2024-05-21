from flask import jsonify
from werkzeug.http import HTTP_STATUS_CODES

from app import app


def error_response(status_code, message=None):
    payload = {'error': HTTP_STATUS_CODES.get(status_code, 'Unknown error')}
    if message:
        payload['message'] = message
    response = jsonify(payload)
    response.status_code = status_code
    app.logger.error(f"Error response: {response}")
    print(f"Error response: {message}")
    return response


def bad_request(message):
    return error_response(400, message)

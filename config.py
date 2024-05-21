class Config(object):
    SQLALCHEMY_DATABASE_URI = (
        'postgresql://chevulahaarvish:@localhost:5432/movies_db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    ENVIRONMENT = 'development'
    SECRET_KEY = "powerful secretkey"
    SECURITY_PASSWORD_SALT = "salt"
    WTF_CSRF_SECRET_KEY = "a csrf secret key"
    JWT_SECRET_KEY = 'jwt-secret-string'
    JWT_COOKIE_SECURE = False
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_ACCESS_TOKEN_EXPIRES = 360000000
    JWT_REFRESH_TOKEN_EXPIRES = 60000

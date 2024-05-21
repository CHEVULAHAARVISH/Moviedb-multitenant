from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from sqlalchemy import MetaData
from config import Config

# Create a Flask application instance
app = Flask(__name__)
# Load the configuration from the Config class
app.config.from_object(Config)

# Define the naming convention for SQLAlchemy
convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

# Create a MetaData instance with the naming convention
metadata = MetaData(naming_convention=convention)
# Create a SQLAlchemy instance with the Flask application and metadata
db = SQLAlchemy(app, metadata=metadata)
# Create a Migrate instance with the Flask application and SQLAlchemy
migrate = Migrate(app, db, render_as_batch=True)

# Create a LoginManager instance with the Flask application
login = LoginManager(app)
# Create a JWTManager instance with the Flask application
jwt = JWTManager(app)

# Import the views and models modules
from app import views, models

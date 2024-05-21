import json
import uuid
from collections import OrderedDict

from flask import g
from flask_jwt_extended import current_user
from flask_login import UserMixin
from sqlalchemy import func, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Query
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login


# This decorator is used to make a class multi-tenant
def multitenant(cls):
    """
    Decorator to make a class multi-tenant.
    :param cls: The class to be made multi-tenant
    :return: The class with the query_class attribute set to CustomQuery
    """
    cls.query_class = CustomQuery
    return cls


# This class is used to create a custom query class for multi-tenant classes
class CustomQuery(Query):
    """
    Custom query class for multi-tenant classes.
    It overrides the filter_by, all, insert, and filter methods of the Query class.
    """

    # This method is used to filter the query by the organization_id
    def filter_by(self, **kwargs):
        """
        Method to filter the query by the organization_id.
        :param kwargs: The filter parameters
        :return: The filtered query
        """
        if g.client_id is None:
            raise Exception('Client ID is not set')
        kwargs['client_id'] = g.client_id
        return super(CustomQuery, self).filter_by(**kwargs)

    # This method is used to get all the records of the query filtered by the organization_id
    def all(self, **kwargs):
        """
        Method to get all the records of the query filtered by the organization_id.
        :param kwargs: The filter parameters
        :return: The filtered query
        """
        if g.client_id is None:
            raise Exception('Client ID is not set')
        kwargs['client_id'] = g.client_id
        return super(CustomQuery, self).filter_by(**kwargs)

    # This method is used to insert a record into the query with the organization_id
    def insert(self, values, **kwargs):
        """
        Method to insert a record into the query with the organization_id.
        :param values: The values to be inserted
        :param kwargs: The insert parameters
        :return: The inserted record
        """
        if g.client_id is None:
            raise Exception('Client ID is not set')
        values['client_id'] = g.client_id
        return super(CustomQuery, self).insert(values, **kwargs)

    # This method is used to filter the query by the organization_id and other criteria
    def filter(self, *criterion):
        """
        Method to filter the query by the organization_id and other criteria.
        :param criterion: The filter criteria
        :return: The filtered query
        """
        if g.client_id is None:
            raise Exception('Client ID is not set')
        columns = self.column_descriptions
        entity = None
        for column in columns:
            if hasattr(column['entity'], 'organization_id'):
                entity = column['entity']
                break
        criterion += (entity.client_id == g.client_id,)
        return super().filter(*criterion)


# This mixin is used to serialize a class to a dictionary
class SerializeMixin:
    """
    Mixin to serialize a class to a dictionary.
    It provides the to_dict method to serialize the class.
    """

    def to_dict(self):
        """
        Method to serialize the class to a dictionary.
        :return: The serialized dictionary
        """
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = getattr(self, key)
        return result


# This function is used to get the current user id or None
def _current_user_id_or_none():
    """
    Function to get the current user id or None.
    :return: The current user id or None
    """
    try:
        return current_user.id
    except Exception as e:
        return None


# This mixin is used to add audit fields to a class
class AuditMixin:
    """
    Mixin to add audit fields to a class.
    It provides the created_at, created_by, updated_at, and updated_by fields.
    """
    created_at = db.Column(db.DateTime, default=func.now())
    created_by = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'),
                           default=_current_user_id_or_none)
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())
    updated_by = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'),
                           default=_current_user_id_or_none)


# This mixin is used to add a client_id field to a class
class ClientMixin:
    """
    Mixin to add a client_id field to a class.
    It provides the client_id field and initializes it in the constructor.
    """
    client_id = db.Column(UUID(as_uuid=True), db.ForeignKey(
        'users.id'), nullable=False)

    def __init__(self, **kwargs):
        """
        Constructor to initialize the client_id field.
        :param kwargs: The constructor parameters
        """
        super().__init__(**kwargs)
        self.client_id = g.client_id


# This class is used to represent a user
class User(UserMixin, AuditMixin, SerializeMixin, db.Model):
    """
    Class to represent a user.
    It extends the UserMixin, AuditMixin, and SerializeMixin classes and the db.Model class.
    It provides the id, name, email, domain, password_hash, status, deleted_at, deleted_by fields and the to_dict, __repr__, set_password, and check_password methods.
    """
    __tablename__ = 'users'
    id = db.Column(UUID(as_uuid=True), default=uuid.uuid4,
                   primary_key=True, unique=True, nullable=False)
    name = db.Column(db.String(128), default="New User", nullable=False)
    email = db.Column(db.String(128), index=True)
    domain = db.Column(db.String(128), default=None)
    password_hash = db.Column(db.String(128))
    status = db.Column(db.String(32))
    deleted_at = db.Column(db.DateTime, default=None)
    deleted_by = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), default=None)

    __table_args__ = (db.UniqueConstraint('email', 'name', 'domain', 'deleted_at'),)

    # This method is used to serialize the user to a dictionary
    def to_dict(self):
        """
        Method to serialize the user to a dictionary.
        :return: The serialized dictionary
        """
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    # This method is used to represent the user as a string
    def __repr__(self):
        """
        Method to represent the user as a string.
        :return: The string representation of the user
        """
        return '<User {}>'.format(self.email)

    # This method is used to set the password of the user
    def set_password(self, password):
        """
        Method to set the password of the user.
        :param password: The password to be set
        """
        self.password_hash = generate_password_hash(password)

    # This method is used to check the password of the user
    def check_password(self, password):
        """
        Method to check the password of the user.
        :param password: The password to be checked
        :return: True if the password is correct, False otherwise
        """
        return check_password_hash(self.password_hash, password)


# This class is used to represent a movie
@multitenant
class Movie(ClientMixin, AuditMixin, SerializeMixin, db.Model):
    """
    Class to represent a movie.
    It extends the ClientMixin, AuditMixin, and SerializeMixin classes and the db.Model class.
    It provides the id, title, year, genre, deleted_at fields and the to_dict and __repr__ methods.
    """
    __tablename__ = 'movies'
    id = db.Column(UUID(as_uuid=True), default=uuid.uuid4,
                   primary_key=True, unique=True, nullable=False)
    title = db.Column(db.String(128), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    genre = db.Column(db.String(128), nullable=False)
    deleted_at = db.Column(db.DateTime, default=None)
    __table_args__ = (db.UniqueConstraint('client_id', 'title', 'deleted_at'),)

    # This method is used to represent the movie as a string
    def __repr__(self):
        """
        Method to represent the movie as a string.
        :return: The string representation of the movie
        """
        return '<Movie {}>'.format(self.title)

    # This method is used to serialize the movie to a dictionary
    def to_dict(self):
        """
        Method to serialize the movie to a dictionary.
        :return: The serialized dictionary
        """
        return {
            'id': self.id,
            'title': self.title,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'year': self.year,
            'genre': self.genre
        }


# This function is used to load a user
@login.user_loader
def load_user(user_id):
    """
    Function to load a user.
    :param user_id: The id of the user to be loaded
    :return: The loaded user
    """
    return User.query.get(int(user_id))

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


def multitenant(cls):
    cls.query_class = CustomQuery
    return cls


class CustomQuery(Query):
    def filter_by(self, **kwargs):
        if g.organization_id is None:
            raise Exception('Organization ID is not set')
        kwargs['organization_id'] = g.organization_id
        return super(CustomQuery, self).filter_by(**kwargs)

    def all(self, **kwargs):
        if g.organization_id is None:
            raise Exception('Organization ID is not set')
        kwargs['organization_id'] = g.organization_id
        return super(CustomQuery, self).filter_by(**kwargs)

    def insert(self, values, **kwargs):
        if g.organization_id is None:
            raise Exception('Organization ID is not set')
        values['organization_id'] = g.organization_id
        return super(CustomQuery, self).insert(values, **kwargs)

    def filter(self, *criterion):
        if g.organization_id is None:
            raise Exception('Organization ID is not set')
        columns = self.column_descriptions
        entity = None
        for column in columns:
            if hasattr(column['entity'], 'organization_id'):
                entity = column['entity']
                break
        criterion += (entity.organization_id == g.organization_id,)
        return super().filter(*criterion)


class SerializeMixin:
    def to_dict(self):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = getattr(self, key)
        return result


def _current_user_id_or_none():
    try:
        return current_user.id
    except Exception as e:
        return None


class AuditMixin:
    created_at = db.Column(db.DateTime, default=func.now())
    created_by = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'),
                           default=_current_user_id_or_none)
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())
    updated_by = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'),
                           default=_current_user_id_or_none)


class ClientMixin:
    client_id = db.Column(UUID(as_uuid=True), db.ForeignKey(
        'users.id'), nullable=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client_id = g.client_id


class User(UserMixin, AuditMixin, SerializeMixin, db.Model):
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

    # Implemented as password_hash should not be part of the dict
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    def __repr__(self):
        return '<User {}>'.format(self.email)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@multitenant
class Movie(ClientMixin, AuditMixin, SerializeMixin, db.Model):
    __tablename__ = 'movies'
    id = db.Column(UUID(as_uuid=True), default=uuid.uuid4,
                   primary_key=True, unique=True, nullable=False)
    title = db.Column(db.String(128), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    genre = db.Column(db.String(128), nullable=False)
    deleted_at = db.Column(db.DateTime, default=None)
    __table_args__ = (db.UniqueConstraint('client_id', 'title', 'deleted_at'),)

    def __repr__(self):
        return '<Movie {}>'.format(self.title)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'year': self.year,
            'genre': self.genre
        }


@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

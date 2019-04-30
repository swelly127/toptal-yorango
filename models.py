import os
import jwt

from mongoengine import *
from enum import IntEnum
import datetime

SECRET_KEY = os.environ.get('SECRET_KEY', '')
class Role(IntEnum):
    TENANT = 0
    REALTOR = 1
    ADMIN = 2

class User(Document):
    created_at = DateTimeField(default=datetime.datetime.now)
    email = EmailField(required=True, unique=True)
    password = StringField(max_length=200)
    role = IntField(default=0)
    meta = {'strict': False}

    def serialize(self):
        return {
            'id': str(self.id),
            'created_at': self.created_at,
            'email': self.email,
            'role': self.role,
        }

    @staticmethod
    def encode_auth_token(user_id):
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=3600),
            'iat': datetime.datetime.utcnow(),
            'sub': str(user_id)
        }
        return jwt.encode(
            payload,
            SECRET_KEY,
            algorithm = 'HS256'
        )

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, SECRET_KEY)
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

class Listing(Document):
    title = StringField(max_length=120)
    description = StringField(max_length=512)
    sq_ft = IntField()
    monthly_rent = IntField()
    num_rooms = IntField()
    realtor = ObjectIdField()
    coordinates = PointField()
    address = StringField(max_length=120)
    is_available = BooleanField()
    occupied_by = ObjectIdField()
    created_at = DateTimeField(default=datetime.datetime.now)
    def serialize(self):
        return {
            'id': str(self.id),
            'title': self.title,
            'description': self.description,
            'sq_ft': self.sq_ft,
            'monthly_rent': self.monthly_rent,
            'num_rooms': self.num_rooms,
            'realtor': str(self.realtor),
            'coordinates': self.coordinates,
            'address': self.address,
            'is_available': self.is_available,
            'occupied_by': self.occupied_by,
            'created_at': self.created_at,
        }

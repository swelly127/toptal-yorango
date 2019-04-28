from mongoengine import *
from enum import IntEnum
from datetime import datetime

class Role(IntEnum):
    TENANT = 0
    REALTOR = 1
    ADMIN = 2

class User(Document):
    created_at = DateTimeField(default=datetime.now)
    email = EmailField(required=True)
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
    created_at = DateTimeField(default=datetime.now)
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

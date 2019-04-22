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
    disabled = BooleanField(default=False)
    meta = {'strict': False}

class Listing(Document):
    title = StringField(max_length=120)
    description = StringField(max_length=512)
    sq_ft = IntField()
    monthly_rent = IntField()
    num_rooms = IntField()
    realtor = ObjectIdField()
    coordinates = PointField()
    address = StringField(max_length=120)
    is_available = BooleanField(default=True)
    occupied_by = ObjectIdField()
    created_at = DateTimeField(default=datetime.now)

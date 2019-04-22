from mongoengine import *
from enum import Enum
from datetime import datetime

class User(Document):
    created_at = DateTimeField(default=datetime.now)
    email = EmailField(required=True)
    first_name = StringField(max_length=50)
    last_name = StringField(max_length=50)
    password = StringField(max_length=200)
    is_realtor = BooleanField(default=False)
    is_admin = BooleanField(default=False)
    disabled = BooleanField(default=False)

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

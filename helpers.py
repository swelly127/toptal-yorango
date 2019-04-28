from geopy.geocoders import Nominatim
from models import *
from flask import request, session

geolocator = Nominatim(user_agent="yorango")

def delete_user():
    if session['user'].get('role') != Role.ADMIN and session['user']['id'] != request.user['id']:
        return "Permission denied", 403
    request.user.delete()
    return "User deleted", 200

def delete_listing():
    if session['user']['id'] == str(request.listing.realtor) or session['user']['role'] == Role.ADMIN:
        request.listing.delete()
        return "Listing deleted", 200
    return "You do not have permission to delete this listing", 403

def update_user():
    if session['user'].get('role') != Role.ADMIN and session['user']['id'] != request.user['id']:
        return "Permission denied", 403
    email = request.form.get('email', default='')
    password = request.form.get('password', default='')
    role = request.form.get('role', default=None)
    update_data = dict()
    if role is not None:
        update_data["set__role"] = int(role)
    if email:
        update_data["set__email"] = email
    if password:
        update_data["password"] = password
    request.user.modify(**update_data)
    return "User updated", 200

def update_listing():
    if session['user'].get('role') != Role.ADMIN and str(request.listing.realtor) != session['user']['id']:
        return "Permission denied", 403
    update_fields = ['title', 'description', 'sq_ft', 'num_rooms', 'monthly_rent', 'address']
    update_data = dict()
    for field in update_fields:
        val = request.form.get(field, None)
        if val is None:
            continue
        if field in ["sq_ft", "num_rooms", "monthly_rent"]:
            update_data["set__" + field] = int(val)
        else:
            update_data["set__" + field] = val
    is_available = request.form.get('is_available', None)
    address = request.form.get('address', None)
    location = geolocator.geocode(address)
    if address:
        update_data["set__address"] = address
    if is_available is not None:
        update_data["set__is_available"] = is_available == "true"
    if location:
        update_data["set__coordinates"] = [location.longitude, location.latitude]
    request.listing.modify(**update_data)
    return "Updated listing", 200

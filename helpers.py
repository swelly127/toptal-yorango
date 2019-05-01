import bson

from flask import request, session
from geopy.geocoders import Nominatim

from models import *

geolocator = Nominatim(user_agent="yorango")

VERY_LARGE_INT = 100000000

def create_user(bcrypt):
    email = request.form.get('email')
    password = request.form.get('password')
    error_msg = None
    if not email:
        error_msg = 'Email is required.'
    elif not password:
        error_msg = 'Password is required.'
    elif User.objects(email=email).first():
        error_msg = 'User with email `{0}` is already registered.'.format(email)
    if error_msg:
        return None, error_msg
    new_user = User(email=email, password=bcrypt.generate_password_hash(password))
    new_user.role = int(request.form.get('role', Role.TENANT))
    new_user.save()
    return new_user, None

def get_current_user():
    current_user = session.get('user', None)
    if current_user is None:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None
        auth_token = auth_header.split(" ")[1]
        user_id = User.decode_auth_token(auth_token)
        if not bson.objectid.ObjectId.is_valid(user_id):
            return user_id
        current_user = User.query.filter_by(id=user_id).first()
        session['user'] = current_user.serialize()
    return current_user

def delete_user():
    if session['user'].get('role') != Role.ADMIN and session['user']['id'] != request.user['id']:
        return "Permission denied", 403
    request.user.delete()
    return "User deleted", 200

def update_user(bcrypt):
    if session['user'].get('role') != Role.ADMIN and session['user']['id'] != request.user['id']:
        return "Permission denied", 403
    email = request.form.get('email', default='')
    password = request.form.get('password', default='')
    role = request.form.get('role', default=None)
    password = request.form.get('password', default=None)
    confirmPassword = request.form.get('confirmPassword', default=None)
    update_data = dict()
    if role is not None:
        update_data["set__role"] = int(role)
    if email:
        update_data["set__email"] = email
    if password and confirmPassword and password == confirmPassword:
        update_data["set__password"] = bcrypt.generate_password_hash(password)
    request.user.modify(**update_data)
    return "User updated", 200

def create_listing():
    title = request.form.get('name')
    description = request.form.get('description', '')
    sq_ft = request.form['sq_ft']
    num_rooms = request.form['num_rooms']
    monthly_rent = request.form['monthly_rent']
    address = request.form['address']
    location = geolocator.geocode(address)
    is_available = request.form.get('is_available') == "true"
    new_listing = Listing(
        title=title,
        description=description,
        sq_ft=sq_ft,
        num_rooms=num_rooms,
        monthly_rent=monthly_rent,
        address=address,
        is_available=is_available,
        realtor=User.objects(email=session['user']['email']).first().id,
    )
    if location:
        new_listing.coordinates = [location.longitude, location.latitude]
    new_listing.save()
    return new_listing

def delete_listing():
    if session['user']['id'] == str(request.listing.realtor) or session['user']['role'] == Role.ADMIN:
        request.listing.delete()
        return "Listing deleted", 200
    return "You do not have permission to delete this listing", 403

def get_listings_info():
    price_low = request.args.get('price_low', default=0, type=int)
    price_high = request.args.get('price_high', default=VERY_LARGE_INT, type=int) # Equal to $100M rent
    size_max = request.args.get('size_max', default=VERY_LARGE_INT, type=int) # Equal to 2300 acres
    size_min = request.args.get('size_min', default=0, type=int)
    num_rooms_max = request.args.get('num_rooms_max', default=VERY_LARGE_INT, type=int)
    num_rooms_min = request.args.get('num_rooms_min', default=0, type=int)
    listings = Listing.objects(
        monthly_rent__lte=price_high,
        monthly_rent__gte=price_low,
        sq_ft__lte=size_max,
        sq_ft__gte=size_min,
        num_rooms__lte=num_rooms_max,
        num_rooms__gte=num_rooms_min,
    )
    markers = []
    sum_latitude, sum_longitude = 0, 0
    for listing in listings:
        if listing.coordinates:
            latitude = listing.coordinates['coordinates'][1]
            longitude = listing.coordinates['coordinates'][0]
            sum_longitude += longitude
            sum_latitude += latitude
            markers.append({
                'lat': latitude, 'lng':longitude,
                'infobox': "<div><a href='listings/%s'>%s for $%s</a></div>" % (str(listing.id), listing.title, listing.monthly_rent)})
    starting_latitude, starting_longitude = 0, 0
    if len(markers) > 0:
        starting_latitude = sum_latitude/len(markers)
        starting_longitude = sum_longitude/len(markers)
    return listings, starting_latitude, starting_longitude, markers

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

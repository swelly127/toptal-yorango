import bson
import logging
import os

from flask import Flask, jsonify, request, session, redirect, url_for, render_template, flash
from flask_bcrypt import Bcrypt
from flask_restful import Resource, Api
from flask_wtf.csrf import CSRFProtect
from flask_googlemaps import GoogleMaps, Map
from functools import wraps
from geopy.geocoders import Nominatim
from models import *
from helpers import *
from resources import *

mongo_host = os.getenv('MONGOLAB_URI', 'mongodb://localhost:27017')
connect(alias='default', host=mongo_host)

app = Flask(__name__)
app.config.from_object('settings')
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

api = Api(app, prefix="/api/v1")

GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY', "")
GoogleMaps(app, key=GOOGLE_API_KEY)

geolocator = Nominatim(user_agent="yorango")

VERY_LARGE_INT = 100000000

def get_current_user():
    current_user = session.get('user', None)
    if current_user is None:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None
        auth_token = auth_header.split(" ")[1]
        user_id = User.decode_auth_token(auth_token)
        if not bson.objectid.ObjectId.is_valid(user_id):
            return None
        return User.query.filter_by(id=user_id).first()
    return current_user

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if type(current_user) is str:
            return current_user, 401
        if current_user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if type(current_user) is str:
            return current_user, 401
        if current_user is None:
            flash('This action is only allowed for site admins. Please login to an admin account.')
            return redirect(url_for('login', next=request.url))
        elif current_user['role'] < 2:
            flash('This action is only allowed for site admins.')
            return redirect(url_for('index'))
        else:
            return f(*args, **kwargs)
    return decorated_function

def realtor_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = get_current_user()
        if type(current_user) is str:
            return current_user, 401
        if current_user is None:
            flash('This action is only allowed for site admins. Please login to an admin or realtor account.')
            return redirect(url_for('login', next=request.url))
        elif current_user['role'] < 1:
            flash('This action is only allowed for site admins and realtors.')
            return "Permission denied", 403
        else:
            return f(*args, **kwargs)
    return decorated_function

def find_listing(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        listing_id = kwargs.get('listing_id', None)
        if listing_id:
            if not bson.objectid.ObjectId.is_valid(listing_id):
                flash('This is not a valid listing id.')
                return render_template('base.html', baseMsg="Invalid listing id."), 404
            listing = Listing.objects(id=listing_id).first()
            if not listing:
                flash('Listing not found.')
                return render_template('base.html', baseMsg="Listing not found."), 404
            request.listing = listing
        return f(*args, **kwargs)
    return decorated_function

def find_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = kwargs.get('user_id', None)
        if user_id:
            if not bson.objectid.ObjectId.is_valid(user_id):
                flash('This is not a valid user id.')
                return render_template('base.html', baseMsg="Invalid user id."), 404
            user = User.objects(id=user_id).first()
            if not user:
                flash('User not found.')
                return render_template('base.html', baseMsg="User not found."), 404
            request.user = user
        return f(*args, **kwargs)
    return decorated_function

class SingleUserResource(Resource):
    @login_required
    @find_user
    def get(self, user_id):
        if session['user'].get('role') == Role.ADMIN or session['user']['id'] == request.user['id']:
            return jsonify(request.user.serialize())
        return "Permission denied", 403

    @login_required
    @find_user
    def put(self, user_id):
        return update_user(bcrypt=bcrypt)

    @login_required
    @find_user
    def delete(self, user_id):
        return delete_user()

class SingleListingResource(Resource):
    @login_required
    @find_listing
    def get(self, listing_id):
        if session['user'].get('role') == Role.TENANT and not request.listing.is_available:
            return "Permission denied", 403
        return jsonify(request.listing.serialize())

    @realtor_or_admin_required
    @find_listing
    def delete(self, listing_id):
        return delete_listing()

    @realtor_or_admin_required
    @find_listing
    def put(self, listing_id):
        return update_listing()

class UserResource(Resource):
    @admin_required
    def get(self):
        users = User.objects.all()
        return jsonify([u.serialize() for u in users])

    def post(self):
        email = request.form.get('email')
        password = request.form.get('password')
        client = request.form.get('client')
        error_msg = None
        if not email:
            error_msg = 'Email is required.'
        elif not password:
            error_msg = 'Password is required.'
        elif User.objects(email=email).first():
            error_msg = 'User with email `{0}` is already registered.'.format(email)
        elif error_msg:
            if client == "web":
                flash(error_msg)
                return redirect(url_for('register'))
            return error_msg, 400
        new_user = User(email=email, password=bcrypt.generate_password_hash(password))
        new_user.role = int(request.form.get('role')) or Role.TENANT
        new_user.save()
        if client == "web":
            return redirect(url_for('login'))
        token = User.encode_auth_token(new_user.id)
        return "User created with auth token %s" % token, 200

class ListingResource(Resource):
    @login_required
    def get(self):
        listings = Listing.objects.all()
        return jsonify([l.serialize() for l in listings if l.is_available or session['user']['role'] > 0])

    @realtor_or_admin_required
    def post(self):
        if session.get('user') is None:
            return redirect(url_for('login'))
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
        if request.form.get("client", None) == "web":
            return redirect('/listings/' + str(new_listing.id))
        return new_listing.serialize(), 200

api.add_resource(SingleUserResource, '/users/<user_id>')
api.add_resource(UserResource, '/users')
api.add_resource(SingleListingResource, '/listings/<listing_id>')
api.add_resource(ListingResource, '/listings')

@app.route('/api/v1/token')
def get_token():
    error = None
    email = request.args.get('email')
    password = request.args.get('password')
    if not email:
        error = 'Email is required.'
    elif not password:
        error = 'Password is required.'
    user = User.objects.get(email=email)
    if not user:
        error = 'User does not exist.'
    elif email != user.email:
        error = 'Invalid email'
    elif bcrypt.check_password_hash(user.password, password) == False:
        error = 'Invalid password'
    if not error:
        token = User.encode_auth_token(user.id)
        session['user'] = user.serialize()
        return jsonify({
            'message': 'success',
            "token": token,
        }), 200
    return jsonify({
        'message': error,
        "token": None,
    }), 400

@app.route('/')
@login_required
def index():
    listings = Listing.objects.all()
    return render_template('index.html', listings=listings)

@app.route('/listings')
@login_required
def listings():
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
    return render_template('listings.html',
        listings=listings, latitude=starting_latitude, longitude=starting_longitude, markers=markers)

@app.route('/listings/new')
@realtor_or_admin_required
def listing_form():
    google_api_script = "https://maps.googleapis.com/maps/api/js?key=" + GOOGLE_API_KEY + "&libraries=places"
    return render_template('listing_form.html', google_api_script=google_api_script)

@app.route('/listings/edit/<listing_id>')
@realtor_or_admin_required
@find_listing
def get_listing_form(listing_id):
    if session['user']['role'] == Role.REALTOR and str(request.listing['realtor']) != session['user']['id']:
        return render_template('base.html', baseMsg="Permission denied. Can only edit listings you own."), 403
    google_api_script = "https://maps.googleapis.com/maps/api/js?key=" + GOOGLE_API_KEY + "&libraries=places"
    return render_template('listing_edit.html', listing=request.listing, google_api_script=google_api_script)

@app.route('/listings/<listing_id>', methods=['POST'])
@realtor_or_admin_required
@find_listing
def post_listing(listing_id):
    if request.form.get("_method") == "PUT":
        msg, code = update_listing()
        flash(msg)
        return redirect('/listings/' + str(listing_id))
    if request.form.get("_method") == "DELETE":
        msg, code = delete_listing()
        flash(msg)
        return redirect(url_for('listings'))
    flash("Invalid method type")
    return redirect('/listings/edit/' + str(listing_id))

@app.route('/listings/<listing_id>', methods=['GET'])
@login_required
@find_listing
def display_listing(listing_id):
    listing_obj = request.listing
    realtor = None
    if listing_obj.realtor:
        realtor = User.objects(id=listing_obj.realtor).first()
    if listing_obj.coordinates:
        latitude = listing_obj.coordinates['coordinates'][1]
        longitude = listing_obj.coordinates['coordinates'][0]
        return render_template('listing.html', listing=listing_obj, map=True, realtor=realtor,
            latitude=latitude, longitude=longitude)
    return render_template('listing.html', map=False, listing=listing_obj, realtor=realtor)

@app.route('/users')
@admin_required
def users():
    users = User.objects.all()
    return render_template('users.html', users=users)

@app.route('/users/edit/<user_id>')
@login_required
@find_user
def get_user_form(user_id):
    if session['user']['id'] == str(request.user['id']) or session['user']['role'] == Role.ADMIN:
        google_api_script = "https://maps.googleapis.com/maps/api/js?key=" + GOOGLE_API_KEY + "&libraries=places"
        return render_template('user_edit.html', user=request.user, google_api_script=google_api_script)
    return render_template('base.html', baseMsg="Permission denied. Can only edit yourself unless admin."), 403

@app.route('/users/<user_id>', methods=['POST'])
@login_required
@find_user
def post_user(user_id):
    if request.form.get("_method") == "DELETE":
        msg, code = delete_user()
        flash(msg)
        return redirect(url_for('users'))
    if request.form.get("_method") == "PUT":
        msg, code = update_user(bcrypt=bcrypt)
        flash(msg)
        return redirect('/api/v1/users/' + user_id)

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        user = User.objects.get(email=email)
        if not user:
            error = 'User does not exist.'
        if email != user.email:
            error = 'Invalid email'
        elif bcrypt.check_password_hash(user.password, password) == False:
            error = 'Invalid password'
        else:
            session['user'] = user.serialize()
            flash('You are now logged in.')
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session['user'] = None
    flash('You are now logged out.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.debug = app.config['DEBUG']
    app.run()

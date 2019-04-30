import bson
import logging
import os

from flask import Flask, jsonify, request, session, redirect, url_for, render_template, flash
from flask_bcrypt import Bcrypt
from flask_restful import Resource, Api
from flask_wtf.csrf import CSRFProtect
from flask_googlemaps import GoogleMaps, Map
from geopy.geocoders import Nominatim

from helpers import *
from middleware import *
from models import *

mongo_host = os.getenv('MONGOLAB_URI', 'mongodb://localhost:27017')
connect(alias='default', host=mongo_host)

app = Flask(__name__)
app.config.from_object('settings')
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

api = Api(app, prefix="/api/v1", decorators=[csrf.exempt])

GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY', "")
GoogleMaps(app, key=GOOGLE_API_KEY)

geolocator = Nominatim(user_agent="yorango")

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
        client = request.form.get('client')
        new_user, error_msg = create_user(bcrypt)
        if client == "web":
            if error_msg:
                flash(error_msg)
                return redirect(url_for('register'))
            flash('You are successfully registered. Welcome!')
            session['user'] = new_user.serialize()
            return redirect(url_for('index'))
        if error_msg:
            return error_msg, 400
        token = User.encode_auth_token(new_user.id)
        return "User created with auth token %s" % token, 200

class ListingResource(Resource):
    @login_required
    def get(self):
        listings = Listing.objects.all()
        return jsonify([l.serialize() for l in listings if l.is_available or session['user']['role'] > 0])

    @realtor_or_admin_required
    def post(self):
        new_listing = create_listing()
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
    user = User.objects(email=email).first()
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
    listings, latitude, longitude, markers = get_listings_info()
    return render_template('listings.html', listings=listings, latitude=latitude, longitude=longitude, markers=markers)

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
        return redirect(url_for('users'))

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

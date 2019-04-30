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
from resources import *

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
        if error_msg:
            if client == "web":
                flash(error_msg)
                return redirect(url_for('register'))
            return error_msg, 400
        new_user = User(email=email, password=bcrypt.generate_password_hash(password))
        new_user.role = int(request.form.get('role', Role.TENANT))
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
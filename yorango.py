import logging
import os

from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_googlemaps import GoogleMaps, Map
from geopy.geocoders import Nominatim
from models import *

mongo_host = os.getenv('MONGOLAB_URI', 'mongodb://localhost:27017')
connect(alias='default', host=mongo_host)

app = Flask(__name__)
app.config.from_object('settings')
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY', "")
GoogleMaps(app, key=GOOGLE_API_KEY)

geolocator = Nominatim(user_agent="yorango")

VERY_LARGE_INT = 100000000

@app.route('/')
def index():
    if session.get('logged_in', False):
        listings = Listing.objects.all()
        return render_template('index.html', listings=listings)
    return redirect(url_for('login'))

@app.route('/listings', methods=['GET', 'POST'])
def listings():
    if request.method == 'POST':
        if session['this_user'] is None:
            return redirect(url_for('login'))
        if not session['this_user']['role']:
            return flash("You don't have permission to create a new listing")
        title = request.form.get('name')
        description = request.form.get('description', '')
        sq_ft = request.form['sq_ft']
        num_rooms = request.form['num_rooms']
        monthly_rent = request.form['monthly_rent']
        address = request.form['address']
        location = geolocator.geocode(address)
        is_available = request.form.get('is_available') == "true"
        new_user = Listing(
            title=title,
            description=description,
            sq_ft=sq_ft,
            num_rooms=num_rooms,
            monthly_rent=monthly_rent,
            address=address,
            is_available=is_available,
            realtor=User.objects(email=session['this_user']['email']).first().id,
        )
        if location:
            new_user.coordinates = [location.longitude, location.latitude]
        new_user.save()
        return redirect(url_for('listings'))
    price_low = request.form.get('price_low', 0)
    price_high = request.form.get('price_high', VERY_LARGE_INT) # Equal to $100M rent
    size_max = request.form.get('size_max', VERY_LARGE_INT) # Equal to 2300 acres
    size_min = request.form.get('size_min', 0)
    num_rooms_max = request.form.get('num_rooms_max', VERY_LARGE_INT)
    num_rooms_min = request.form.get('num_rooms_min', 0)
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
    starting_latitude = sum_latitude/len(markers)
    starting_longitude = sum_longitude/len(markers)
    return render_template('listings.html',
        listings=listings, latitude=starting_latitude, longitude=starting_longitude, markers=markers)

@app.route('/listings/new')
def listing_form():
    google_api_script = "https://maps.googleapis.com/maps/api/js?key=" + GOOGLE_API_KEY + "&libraries=places"
    return render_template('listing_form.html', google_api_script=google_api_script)

@app.route('/listings/<listing_id>', methods=['GET', 'PUT', 'DELETE'])
def single_listing(listing_id):
    if request.method == 'PUT':
        return None
    if request.method == 'DELETE':
        Listing.objects(id=listing_id).delete()
        flash('Listing has been deleted.')
        return redirect(url_for('listings'))
    listing_obj = Listing.objects(id=listing_id).first()
    if listing_obj:
        if listing_obj.coordinates:
            latitude = listing_obj.coordinates['coordinates'][1]
            longitude = listing_obj.coordinates['coordinates'][0]
            return render_template('listing.html', listing=listing_obj, map=True, latitude=latitude, longitude=longitude)
        return render_template('listing.html', map=False, listing=listing_obj)
    return "Listing %s not found" & listing_id

@app.route('/users')
def users():
    if session['this_user']['role'] != Role.ADMIN:
        flash('Only site admins have permission to view other users.')
        return redirect(url_for('index'))
    users = User.objects.all()
    return render_template('users.html', users=users)

@app.route('/users/<user_id>', methods=['GET', 'PUT', 'DELETE'])
def single_user(user_id):
    if request.method == 'PUT':
        email = request.form.get('email')
        password = request.form.get('password')
        # todo(jshu): make sure this is correct
        role = request.form.get('role')
        disabled = request.form.get('disabled') == "true"
        update_data = dict(set__role=role, set__is_disabled=disabled)
        if email:
            update_data["set__email"] = email
        if password:
            update_data["password"] = password
        User.objects(id=user_id).modify(upsert=False, new=True, **update_data)
        return None
    if request.method == 'DELETE':
        User.objects(id=user_id).delete()
        flash('User account has been deleted.')
        return redirect(url_for('users'))
    return 'User %s' % user_id

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email:
            return flash('Email is required.')
        elif not password:
            return flash('Password is required.')
        elif User.objects(email=email).first():
            return flash('User with email `{0}` is already registered.'.format(email))
        new_user = User(email=email, password=bcrypt.generate_password_hash(password))
        new_user.role = int(request.form.get('role')) or Role.TENANT
        new_user.save()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email:
            return flash('Email is required.')
        elif not password:
            return flash('Password is required.')
        this_user = User.objects.get(email=email)
        if not this_user:
            return flash('User does not exist.')
        if email != this_user.email:
            error = 'Invalid email'
        elif bcrypt.check_password_hash(this_user.password, password) == False:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            session['this_user'] = {
                'email': this_user.email,
                'role': this_user.role,
                'is_disabled': this_user.disabled,
            }
            flash('You are now logged in.')
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('this_user', None)
    flash('You are now logged out.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.debug = app.config['DEBUG']
    app.run()

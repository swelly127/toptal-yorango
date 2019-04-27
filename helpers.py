from geopy.geocoders import Nominatim
from models import *

geolocator = Nominatim(user_agent="yorango")

def delete_listing(session, listing):
    if session['user'].id == listing.realtor or session['user'].role == ROLE.ADMIN:
        listing.delete()
        return "Listing deleted", 200
    return "You do not have permission to delete this listing", 200

def update_listing(session, request):
    if session['user'].id != request.listing.realtor and session['user'].role != ROLE.ADMIN:
        return "You do not have permission to delete this listing", 200
    update_fields ['title', 'description', 'sq_ft', 'num_rooms', 'monthly_rent', 'address']
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
        updated_data["set__coordinates"] = [location.longitude, location.latitude]
    request.listing.modify(upsert=False, new=True, **update_data)
    return "Listing updated", 200

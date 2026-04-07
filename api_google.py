#!/usr/bin/env python3
import requests
import sys

if len(sys.argv) != 2:
    print("Uso: python3 google_api_test.py <API_KEY>")
    sys.exit(1)

API_KEY = sys.argv[1]

endpoints = {
    "Static Maps": f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={API_KEY}",
    "Street View": f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&key={API_KEY}",
    "Directions": f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={API_KEY}",
    "Geocoding": f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={API_KEY}",
    "Distance Matrix": f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=40.6655101,-73.8918897&destinations=40.6905615,-73.9976592&key={API_KEY}",
    "Find Place": f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&fields=name&key={API_KEY}",
    "Autocomplete": f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key={API_KEY}",
    "Elevation": f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={API_KEY}",
    "Timezone": f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={API_KEY}",
    "Roads": f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795&key={API_KEY}",
}

def check(name, url):
    try:
        r = requests.get(url, timeout=10)
        status = r.status_code

        if "REQUEST_DENIED" in r.text:
            result = "DENIED"
        elif "error" in r.text.lower():
            result = "ERROR"
        elif status == 200:
            result = "OK (Possivelmente vulnerável)"
        else:
            result = f"HTTP {status}"

        print(f"[{result}] {name}")

    except Exception as e:
        print(f"[FAIL] {name} - {e}")

print("\nTestando API Key...\n")
for name, url in endpoints.items():
    check(name, url)

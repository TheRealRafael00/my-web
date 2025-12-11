from http.server import BaseHTTPRequestHandler
import json
import requests
import urllib.parse

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers()

        path = self.path
        if "?num=" not in path:
            self.wfile.write(json.dumps({"error":"no number"}).encode())
            return

        number = urllib.parse.unquote(path.split("?num=")[1])

        info = requests.get("https://api.numlookupapi.com/v1/validate?number="+number).json()

        loc = info.get("location","-")
        geo = requests.get("https://nominatim.openstreetmap.org/search?format=json&q="+urllib.parse.quote(loc)).json()

        lat = geo[0]["lat"] if geo else ""
        lon = geo[0]["lon"] if geo else ""
        info["latitude"] = lat
        info["longitude"] = lon
        info["maps"] = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else "-"

        self.wfile.write(json.dumps(info).encode())

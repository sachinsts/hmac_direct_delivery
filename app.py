from flask import Flask
import hmac, hashlib
from flask import request
import time
import struct
import calendar
import datetime
from binascii import unhexlify
import binascii
import codecs
# from datetime import datetime
import datetime
import requests
import json

app = Flask(__name__)

@app.route("/test")
def hello():
    return "Hello, World!"

def getSignature(data, timestamp):
	secret = '123bnxnhsda78q&*as@'
	message = bytes(data, 'utf-8')
	secret = bytes(secret, 'utf-8')
	
	base = 'v0:%s:%s' % (timestamp.decode('utf-8'), message.decode('utf-8'))
	computed = hmac.new(secret,
						base.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
	sig = 'v0=%s' % (computed,) #this will go to request header
	return sig
	

@app.route("/callapi")
def callapi():
	#this makes call to other API
	url = "http://127.0.0.1:4000/checkapi"
	timestamp = time.time()
	time_stamp_byte = binascii.hexlify(struct.pack('<I', round(timestamp)))
	signature = getSignature(url, time_stamp_byte)
	headers = { 'signature' : signature, 'timestamp': time_stamp_byte }
	response = requests.get(url=url, headers=headers)
	response_dict = json.loads(response.text)
	return response_dict

@app.route("/checkapi")
def checkapi():
	secret = bytes("123bnxnhsda78q&*as@", 'utf-8')
	isvalid = validateSignature(request, secret)
	if(isvalid):
		return jsonify({"status": 200, "msg": "Valid access" })

	return jsonify({"status": 404, "msg": "Invalid access" })


def validateSignature(request, secret):
	timestamp = bytes(request.headers['timestamp'], 'utf-8')
	request_signature = request.headers['signature']
	message = bytes(request.url, 'utf-8')

	sig_basestring = 'v0:%s:%s' % (timestamp.decode('utf-8'), message.decode('utf-8'))
	computed_sha = hmac.new(secret,sig_basestring.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()
	current_signature = 'v0=%s' % (computed_sha,)

	if(request_signature == current_signature):
		return True
	return False


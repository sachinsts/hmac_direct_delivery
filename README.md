# hmac_direct_delivery-1

Installation 
1. Take clone of repo and run command python -m venv venv
2. Run pip install requests
3. Run command flask run --port=5000
4. follow step 1,2 in another location and run command  flask run --port=4000, this will run same application on different port

Verify API is working 
 go to postman and hit this url 127.0.0.1:5000/callapi  it will call API of application running on another port 127.0.0.1:4000/checkapi , 
   which validates incoming request and send response



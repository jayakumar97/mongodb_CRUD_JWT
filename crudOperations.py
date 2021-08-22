from dns import exception
from pymongo import MongoClient
import pymongo
import sys
from flask import Flask, json,session,request,redirect,jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
import uuid
import jwt
import datetime
import os
from bson.objectid import ObjectId

app = Flask(__name__)
#read configuration from app_config.py
app.config.from_object('app_config')


@app.route('/register', methods=['POST'])
def userRegistration(): 
    """Function to register a user"""
    try:    
        data = request.get_json() 
        if data['password'] =="" or data['first_name'] =="" or data['last_name']=="" or data['email'] =="":
                raise exception    
        #One way encryption to staore the password
        hashedPassword = generate_password_hash(data['password'], method='sha256')
        #check user existence before registration(check by mail id)
        if userCollection.count_documents({"email":data['email']}) != 0 :
            return make_response(jsonify({'message': 'User already exist'}),409)
        newUser = {'first_name':data['first_name'], 'last_name':data['last_name'], 'email':data['email'] ,'password':hashedPassword}
        #register the user
        x = userCollection.insert_one(newUser)
        return make_response(jsonify({'message': 'User added successfully'}),200)     
    except Exception as e:
        print(e)
        return make_response(jsonify({'message': 'Error while registering your mail id(please check the input once again)'}),500) 
    

def validateToken(func):
    """Decorator function to check the given token is valid"""
    @wraps(func)
    def decorator(*args, **kwargs):
        token = None
        #check token is given in header
        if 'Authorization' in request.headers:
           token = request.headers['Authorization']
           token=token.replace('Bearer ','')
           
        if not token:
           return make_response(jsonify({'message': 'Token is missing'}),400)
        
        try:
           #decode the token to get regostered user _id
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           #check if the user _id present in user collection or not
           user = userCollection.find_one({"_id" : ObjectId(data['id'])}) 
           if not user:
               raise exception
        except:
            return make_response(jsonify({'message': 'token is invalid'}),400)
        return func(data['id'], *args, **kwargs)
    return decorator

@app.route('/template', methods=['POST','GET'])
@validateToken
def CRudTemplate(userId):
    """ Create and Read template function"""
    if request.method == 'POST':
        # condition to insert a template in collection
        try:
            data = request.get_json() 
            if data['template_name'] =="" or data['subject'] =="" or data['body']=="":
                raise exception
            #assumption template need not to be unique. no explicit condition is given
            template={"userId":userId,"template_name":data['template_name'] ,"subject":data['subject'],"body":data['body']}
            temp=templateCollection.insert_one(template)
        except:
            return make_response(jsonify({'message': 'Error while inserting new template(please check the input once again)'}),500)
        return make_response(jsonify({'message': 'Template inserted successfully'}),200)

    if request.method == 'GET':
        #condition to read all the templates of a user
        try:
            result=templateCollection.find({"userId":userId},{"_id": 0,"template_name":1, "subject": 1, "body": 1})
            temp={}
            if templateCollection.count_documents({"userId":userId}) ==0:
                return make_response(jsonify({'message': 'No template is found'}),404)    
            for x in result:
                print(x)
                temp2={'subject':x['subject'],'body':x['body']}
                temp[x['template_name']]=temp2
            result=jsonify(temp)
            return make_response(result,200)
        except Exception as e:
            print(e)
            return make_response(jsonify({'message': 'Error while fetchig the template'}),500)



@app.route('/template/<template_id>', methods=['GET','PUT','DELETE'])
@validateToken
def cRUDTemplate(userId,template_id):
    """Function to read, update and delete a template"""
    
    if (not template_id) or (len(template_id) != 24) :
        return make_response(jsonify({'message': 'give input template id'}),400)
    try:
        result=templateCollection.find_one({"_id":ObjectId(template_id)})
        #check if the user authorized to access the template
        if not userId == result['userId'] :
            return make_response(jsonify({'message': 'user not authorized to access'}),400)
            
        if request.method == 'GET':
            #condition to read a single document based on given template id
            result={"template_name":result["template_name"],"subject":result['subject'],'body':result['body']}    
            return make_response(jsonify(result),200)
        
        if request.method == 'DELETE':
            #condition to delete a single document based on given template id
            result=templateCollection.find_one_and_delete({"_id":ObjectId(template_id)})
            return make_response(jsonify({'message': 'template deleted succesfully'}),200)
        
        if request.method == 'PUT':
            #condition to update a document
            data = request.get_json() 
            #if input is not given use existing field data
            if not data["template_name"]:
                data['template_name'] = result['template_name']
            if not data["subject"]:
                data['subject']=result['subject']
            if not data["body"]:
                data['body']=result['body']
                 
            result=templateCollection.find_one_and_update ({"_id":ObjectId(template_id)},{"$set":{"template_name":data["template_name"],"subject":data['subject'],'body':data['body']}})
            return make_response(jsonify({'message': 'template updated succesfully'}),200)
    except Exception as e:
        print(e)
        return make_response(jsonify({'message': 'template not found'}),404)


@app.route('/login', methods=['POST']) 
def login_user():
    data = request.get_json() 
    #data validation  
    if not data["email"] or not data["password"]: 
        return make_response(jsonify({'message': 'login details missing'}),401)   
    user = userCollection.find_one({"email" : data["email"]}) 
    #check user existence
    if not user:
        return make_response(jsonify({'message': 'user doesnt exist'}),400)   
    #check whether hash value of password matches
    if check_password_hash(user["password"], data["password"]):
        print(" object id check",user["_id"])
        token = jwt.encode({'id' : str(user["_id"]), 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], "HS256")
        return make_response(jsonify({'token' : token}),200)
    else:
        return make_response(jsonify({'message': 'password is incorrect'}),401)   

def getCollections():
    # connect to mongo atlas 
    client = MongoClient(app.config['CONNECTION_URL'])
    global userCollection
    global templateCollection
    baseDb=client.baseDb
    userCollection=baseDb.userCollection
    templateCollection=baseDb.templateCollection
    return 

    

if __name__ == "__main__":    
    # Get the collections
    getCollections()
    #run the app and expose API endpoint
    app.run(host="localhost",port=5000) 

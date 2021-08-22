import urllib
#connection url to mongodb atlas
CONNECTION_URL = "mongodb+srv://dbAdmin:"+urllib.parse.quote("dbAdmin@123")+"@cluster0.s4wus.mongodb.net/baseDb?retryWrites=true&w=majority"

#use secrets.token_hex to generate secret randomly in production
SECRET_KEY='d1ce12debf4cc3cfcf814c802757bdd6'

from fastapi import FastAPI
from pymongo import MongoClient
from dotenv import load_dotenv

import bcrypt
import jwt
import os
import re
import uuid

load_dotenv()
MONGODB_ATLAS_USER = os.environ["MONGODB_ATLAS_USER"]
MONGODB_ATLAS_PASSWORD = os.environ["MONGODB_ATLAS_PASSWORD"]
MONGODB_ATLAS_CLUSTER = os.environ["MONGODB_ATLAS_CLUSTER"]

cluster = MongoClient(f"mongodb+srv://{MONGODB_ATLAS_USER}:{MONGODB_ATLAS_PASSWORD}@{MONGODB_ATLAS_CLUSTER}/?retryWrites=true&w=majority")
db = cluster.Users
python_mongo = db.users

app = FastAPI()

@app.post("/create_user")
async def create_user(email: str, password: str):
    # name and age maybe optionals here
    message = ""
    if validate_email(email):
      password_encrypted = encrypt_password(password)
      user = {
        "id": uuid.uuid4().hex,
        "email": email,
        "password": password_encrypted,
        "name": email,
        "age": 0,
        "token": None,
      }

      inserted_user = insert_user(user)
      
      if inserted_user.inserted_id:
        message = "User created successfully"
        print(message)

        return {"status": 200, "message": message}
      
      message = "Something went wrong creating the user"
      print(message)
      
      return {"status": 400, "message": message}
    
    message = "Invalid email format"
    print(message)

    return {"status": 400, "message": message}


@app.get("/login/")
async def login(email: str, password: str):
  message = ""
  if validate_email(email):
    user = python_mongo.find_one({"email": email})
    password_match = check_password(password, user["password"])
    import ipdb ; ipdb.set_trace()

    if password_match:
      token = generate_token(user)
      updated_user = update_user(user, token)
      if updated_user:
        user = python_mongo.find_one({"email": email})
        message = {
          "id": user["id"],
          "name": user["name"],
          "age": user["age"],
          "token": user["token"],
        }
        print(message)
        return {"status": 200, "message": message}
      
      message = "Error token generation, please try again"
    
    message = "Invalid credentials, please try again"
    return {"status": 401, "message": message}

  message = "Invalid email format"
  return {"status": 400, "message": message}


def encrypt_password(password: str):
    password_encoded = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password_encoded, salt)
    return hash


def insert_user(user: dict):
  return python_mongo.insert_one(user)


def validate_email(email: str):
   pat = "^[a-zA-Z0-9-_]+@[a-zA-Z0-9]+\.[a-z]{1,3}$"
   if re.match(pat, email):
      return True
   return False


def check_password(password: str, hashed_password: str):
  if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
    return True
  return False


def generate_token(user: dict):
  token = jwt.encode({"email": user["email"]}, user["id"], algorithm="HS256")
  return token


def update_user(user: dict, token: str):
  # ToDo: update name and age
  return python_mongo.update_one({"email": user["email"]}, {"$set": {"token": token}})
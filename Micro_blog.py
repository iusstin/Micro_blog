from flask import Flask, request
import re, hashlib, json
from datetime import datetime

app = Flask(__name__)
users_file = "users.txt"
articles_file = "articles.txt"
articole_citite = "articole_citite.txt"
types = ['0','1']
ID = 0

def verify_user(username):
    result = re.findall("^\D.{0,9}$", username)
    print(bool(result))
   
def check_user(username):
    with open("users.txt", 'r') as f:
        lines = f.readlines()
    for l in lines:
        l = l.split(';')
        if username == l[0]:
            return True
    return False
    
def verify_password(password):
    regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!%*?&]).*$"
    result = re.findall(regex, password)
    return bool(result)
    
def encrypt_pass(password):
   encrypted_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
   return encrypted_password

def write_user(username, password, type):
    createdOn = datetime.now().strftime("%H:%M-%d/%m/%Y")
    data = "{};{};{};{}\n".format(username, encrypt_pass(password), type, createdOn)
    with open("users.txt", 'a+') as u:
        u.write(data)
        
def add_user(user, password, type):
    if not verify_user:
        return "Invalid user name, it can't start with a digit and it must have no more\
        than 10 characters"
    if check_user(user):
        return "user already exists"
    if not verify_password(password):
        return "Invalid password, password must have at least one lowercase letter, \
        uppercase letter,one digit and one special character"
    if str(type) not in types:
        raise Exception("Invalid type of user, must be 0 or 1")
    write_user(user, password, type)
    return "User added successfully"

def verify_title(title):
    t = re.findall("^.{1,50}$", title)
    return bool(t)


def user_info(writer):
    with open("users.txt", 'r') as u:
        lines = u.readlines()
    for l in lines:
        l = l.split(';')
        if writer == l[0]:
            return {
                "encrypted_password":l[1],
                "user_type": l[2]
                }
    return None

def generate_id():
    global ID
    ID += 1
    return ID

def write_article(title, content, writer):
    id = str(generate_id())
    createdOn = datetime.now().strftime("%H:%M-%d/%m/%Y")
    data = "{};{};{};{};{}\n".format(id, title, content, writer, createdOn)
    with open("articles.txt", 'a+', encoding="utf-8") as a:
        a.write(data)

def add_article(title, content, writer, password):
    if not verify_title(title):
        return "Invalid title, can't have more than 50 characters"
    if not check_user(writer):
        return "User doesn't exists."
    info = user_info(writer)
    if encrypt_pass(password) != info["encrypted_password"]:
        raise Exception("Incorrect password")
    if info["user_type"] != '0':
        return "User {} doesn't have rights to publish articles".format(writer)
    write_article(title, content, writer)
    return "Article added successfully"

def get_article(id):
    with open(articles_file, 'r') as a:
        lines = a.readlines()
    for l in lines:
        l = l.split(';')
        if str(id) == l[0]:
            result = {
                "title": l[1],
                "content": l[2],
                "writer": l[3],
                "createdOn": l[4]
                }
            return json.dumps(result)
    return "Article with id {} does not exist!".format(id)

@app.route('/')
def hello_world():
    return "Hello!"
    
@app.route('/user/add', methods = ["POST"])
def addUser():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    user_type = data["user_type"]
    return add_user(username, password, user_type)
    
@app.route('/article/add', methods = ["POST"])
def addArticle():
    data = request.get_json()
    title = data["title"]
    content = data["content"]
    writer = data["writer"]
    password = data["password"]
    return add_article(title, content, writer, password)

@app.route("/article/get")
def getArticle():
    data = request.args
    id = data["id"]
    #print(data["ion"])
    return get_article(id)

    
if __name__ == "__main__":
    app.run(debug=True, port=9999)
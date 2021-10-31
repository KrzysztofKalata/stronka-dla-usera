# from flask import Flask,request, make_response, render_template, session, flash, url_for, g
# from flask_session import Session
# from dotenv import load_dotenv
# from os import getenv
# from bcrypt import hashpw, checkpw, gensalt
# import datetime
# from jwt import encode, decode, InvalidTokenError
# from redis import Redis
# import uuid
# import jwt
# db = Redis(host='redis', port=6379, db=0)
#
# load_dotenv()
# SESSION_TYPE = "redis"
# SESSION_REDIS = db
# JWT_SECRET = getenv('JWT_SECRET')
# app = Flask(__name__)
# app.config.from_object(__name__)
# app.secret_key = getenv("SECRET_KEY")
# ses = Session(app)
#
# def get_packages_list():
#     packages_string = db.hget(f"user:{g.user}", "packages")
#     if packages_string is None:
#         return []
#     else:
#         packages_string = packages_string.decode()
#         pacs = list(packages_string.split(','))
#         return pacs
#
# def get_profile_informations():
#     profile_informations = {
#         "login" : g.user,
#         "firstname" : db.hget(f'user:{g.user}', 'firstname').decode(),
#         "lastname" : db.hget(f'user:{g.user}','lastname').decode(),
#         "address" : db.hget(f'user:{g.user}','address').decode(),
#         "emailAddress" : db.hget(f'user:{g.user}','emailAddress').decode()
#     }
#     return profile_informations
#
# def list_to_string(lista):
#     final_string = ''
#     if len(lista) != 0:
#         for element in lista:
#             final_string += str(element)
#             final_string += ','
#         final_string = final_string[:-1]
#     return final_string
#
# def get_token_by_package(pid):
#     token = db.hget(f"{pid}","token")
#     if token is None:
#         return None
#     token = token.decode()
#     return token
#
# def generate_tracking_token(package_number, username,post_office_box_id,package_size):
#     payload = {
#         "iss" : "HopSiup app",
#         "sub" : package_number,
#         "usr" : username,
#         "aud" : "HopSiup tracking service",
#         "post_office_box_id" : post_office_box_id,
#         "package_size" : package_size,
#         "id" : str(uuid.uuid4())
#     }
#     token = encode(payload, JWT_SECRET, algorithm = 'HS256')
#     return token
#
# @app.before_request
# def get_logged_username():
#     g.user = session.get('username')
#
# def redirect(location):
#     response = make_response("",301)
#     response.headers["Location"] = location
#     return response
#
# def is_user(username):
#     return db.hexists(f"user:{username}", "password")
#
# def save_user(username, password, firstname, lastname, address, emailAddress):
#     password = password.encode('utf-8')
#     db.hset(f"user:{username}", "password", hashpw(password,gensalt(4)))
#     db.hset(f"user:{username}", "firstname", firstname)
#     db.hset(f"user:{username}", "lastname", lastname)
#     db.hset(f"user:{username}", "address", address)
#     db.hset(f"user:{username}", "emailAddress", emailAddress)
#     return True
#
# def verify_user(username, password):
#     db_password = db.hget(f"user:{username}", "password")
#     password = password.encode()
#
#     if not db_password:
#         return False
#     if checkpw(password,db_password):
#         return True
#     return False
#
# @app.route('/')
# def index():
#     return render_template("index.html")
#
# @app.route('/sender/register', methods =['GET'])
# def register_form():
#     return render_template("register.html")
#
# @app.route('/sender/register', methods =['POST'])
# def register():
#     username = request.form.get("login")
#     if not username:
#         flash("Brak loginu")
#
#     firstname = request.form.get("firstname")
#     if not firstname:
#         flash("Brak imienia")
#
#     lastname = request.form.get("lastname")
#     if not lastname:
#         flash("Brak nazwiska")
#
#     address = request.form.get("address")
#     if not address:
#         flash("Brak adresu")
#
#     emailAddress = request.form.get("emailAddress")
#     if not emailAddress:
#         flash("Brak adresu e-mail")
#
#     password = request.form.get("password")
#     if not password:
#         flash("Brak hasla")
#         return redirect(url_for("register_form"))
#
#     confirmPassword = request.form.get("confirmPassword")
#     if confirmPassword != password:
#         flash("Hasla nie sa zgodne")
#         return redirect(url_for("register_form"))
#
#     if username and password and firstname and lastname and address and emailAddress:
#         if is_user(username):
#             flash("Uzytkownik jest juz zarejestrowany")
#             return redirect(url_for("register_form"))
#
#         try_save = save_user(username,password,firstname,lastname,address,emailAddress)
#         if not try_save:
#             flash("Blad przy rejestracji")
#             return redirect(url_for("register_form"))
#
#     return redirect(url_for("login_form"))
#
# @app.route('/sender/login', methods = ['GET'])
# def login_form():
#     return render_template("login.html")
#
# @app.route('/sender/login', methods = ['POST'])
# def login():
#     username = request.form.get("login")
#     password = request.form.get("password")
#     if not username or not password:
#         flash("Brak loginu lub hasla")
#         return redirect(url_for("login_form"))
#     if not verify_user(username, password):
#         flash("Błędny login lub hasło")
#         return redirect(url_for("login_form"))
#
#     flash(f"Witaj {username}!")
#     session['username'] = username
#     session[username] = "Logged-at: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#
#     return redirect(url_for('dashboard'))
#
# @app.route('/sender/logout', methods = ["POST"])
# def logout():
#     cookie = request.cookies.get('session')
#     if cookie:
#         delete_success = db.delete('session:'+ cookie)
#         if delete_success == 0:
#             flash('Podczas wylogowywania wystąpił błąd')
#     session.clear()
#     g.user = None
#
#     flash('Pomyslnie wylogowano!')
#     return redirect(url_for('login_form'))
#
# @app.route('/sender/dashboard')
# def dashboard():
#     if g.user is None:
#         return 'Not authorized',401
#     pids = get_packages_list()
#     tokens = {}
#     for pid in pids:
#         tokens[pid] = get_token_by_package(pid)
#     return render_template("dashboard.html", tokens=tokens, no_packages = (len(tokens) == 0))
#
# @app.route('/package/<pid>', methods = ['GET'])
# def get_package(pid):
#     token = request.args.get('token')
#     if token is None:
#         return 'Brak tokena',401
#     try:
#         payload = decode(token, JWT_SECRET, algorithm = 'HS256', audience = "HopSiup tracking service")
#     except jwt.InvalidTokenError as error:
#         return 'Invalid access token',401
#     if pid != str(payload.get('sub')):
#         return 'Not authorized',401
#     return render_template('package.html', package_info = payload)
#
# @app.route('/package/<pid>/delete', methods = ["POST"])
# def delete_package(pid):
#     pacs = get_packages_list()
#     pacs.remove(pid)
#     if list_to_string(pacs) == '':
#         db.hdel(f'user:{g.user}',"packages")
#     else:
#         db.hset(f'user:{g.user}', 'packages', list_to_string(pacs))
#     db.delete(pid)
#     return redirect(url_for('dashboard'))
#
# @app.route('/package/create', methods = ["POST"])
# def create_package():
#     username = g.user
#     post_office_box_id = request.form.get('post_office_box_id')
#     package_size = request.form.get('package_size')
#     pacs = get_packages_list()
#
#     if not pacs:
#         package_number = g.user + ':' + '10000'
#     else:
#         package_number = g.user + ':' + str(int(pacs[-1][-5:]) + 1)
#
#     token_value = generate_tracking_token(package_number,username,post_office_box_id,package_size).decode()
#     db.hset(package_number,"token", token_value)
#     pacs.append(package_number)
#     db.hset(f'user:{g.user}', 'packages', list_to_string(pacs))
#
#     return redirect(url_for('dashboard'))
#
# @app.route('/sender/profile', methods = ['GET'])
# def profile_form():
#     if g.user is None:
#         return 'Not authorized',401
#     profile_informations = get_profile_informations()
#     return render_template('profile.html', profile_informations=profile_informations)
#
#
# if __name__ == '__main__':
#     print("uruchamiamy")
#     app.run()

from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello World!"
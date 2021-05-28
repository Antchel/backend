import hashlib
import uuid
import bcrypt
from flask import Flask,session, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, \
    set_access_cookies, get_jwt_identity, create_refresh_token
import sqlite3 as lite
import datetime
from flask_jwt_extended.exceptions import NoAuthorizationError

con = lite.connect('link_shortener.db', check_same_thread=False)
cur = con.cursor()

client_port = 5000

cur.execute('CREATE TABLE IF NOT EXISTS urls ('
            'id INTEGER PRIMARY KEY AUTOINCREMENT,'
            'created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,'
            'original_url TEXT NOT NULL,'
            'short_url TEXT,'
            'human_url TEXT,'
            'link_type INTEGER,'
            'username TEXT,'
            'clicks INTEGER NOT NULL DEFAULT 0)')

cur.execute('CREATE TABLE IF NOT EXISTS users ('
            'id	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
            'username	TEXT NOT NULL UNIQUE,'
            'password	TEXT NOT NULL)')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sdgjh48i3kjg'

app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies', "query_string", "json"]
app.config["JWT_COOKIE_SECURE"] = False
# Change this in your code!
app.config["JWT_SECRET_KEY"] = "lkdspcol2DS43r3DCSsd"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
jwt = JWTManager(app)
salt = bcrypt.gensalt()
expiration_time = 200


@app.route('/register', methods=['GET', 'POST', 'OPTIONS'])
def register():
    form = request.args.to_dict()
    if request.method == "POST":
        if form["password"] != form["valid_password"]:
            return jsonify({'msg': "Passwords are incompatible. Please reenter passwords"}), 404
        user = cur.execute("Select id from users where username = ?", (form['password'],)).fetchone()
        if user:
            return jsonify({'msg': "Such login is used, please choose another one"}), 404
        hash_pass = bcrypt.hashpw(form["password"].encode("utf8"), salt).decode("utf8")
        cur.execute('Insert into users (username, password) VALUES (?,?)', (form["username"], hash_pass))
        con.commit()
        return jsonify({'msg': "Registration success"}), 201
    if request.method == 'GET':
        return jsonify({'msg': "Registration page"}), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET, POST"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/', methods=['GET', 'POST', 'OPTIONS'])
@app.route('/log', methods=['GET', 'POST'])
def log():
    session['username'] = "guest"
    form = request.args.to_dict()
    if request.method == 'POST':
        usr_pass = cur.execute("SELECT password FROM users WHERE username = ?", (form['username'],)).fetchone()
        if not usr_pass:
            return jsonify({'msg': "Current user doesn't exists"}), 407
        else:
            if bcrypt.checkpw(form['password'].encode("utf8"), usr_pass[0].encode("utf8")):
                session['username'] = form['username']
                refresh_token = create_refresh_token(identity=form['username'],
                                                     expires_delta=datetime.timedelta(seconds=expiration_time))
                access_token = create_access_token(identity=form['username'],
                                                   expires_delta=datetime.timedelta(seconds=expiration_time))
                response = jsonify({'login': True, "JWT": access_token, "refresh_token": refresh_token})
                app.config["JWT_COOKIE_CSRF_PROTECT"] = False
                response.status_code = 200
                return response
            else:
                return jsonify({'msg': "Wrong password"}), 407
    if request.method == 'GET':
        return jsonify({'msg': "Login page"}), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET, POST"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/linkage', methods=['POST', 'OPTIONS'])
def linkage():
    verify_jwt_in_request(locations=['headers', 'cookies'])
    current_user = get_jwt_identity()
    if not get_jwt_identity():
        return jsonify({'msg': 'Login please!'}, 401)
    human_url = None
    form = request.args.to_dict()
    hash_symbols = 8
    if hash_symbols < 8:
        HASH_SIZE = 8
    else:
        HASH_SIZE = int(hash_symbols)
    if request.method == 'POST':
        url = form['source_link']
        short_link = cur.execute("SELECT * FROM urls WHERE short_url = ?", (url,)).fetchall()
        if short_link:
            return jsonify({'msg': 'It is a short url!'}), 401
        var = cur.execute("SELECT * FROM urls WHERE original_url = ? AND username = ?",
                          (url, current_user,)).fetchall()
        if var:
            return jsonify({'msg': 'This url is already exists!'}), 401
        if not url:
            return jsonify({'msg': 'The URL is required!'}), 401
        if not form['human_link']:
            hash_id = hashlib.sha256(uuid.uuid4().hex.encode() + form['source_link'].encode()).hexdigest()[-HASH_SIZE:]
            short_url = request.host_url.partition(":5")[0] + f":{client_port}/" + hash_id
            con.execute('INSERT INTO urls (original_url, short_url, link_type, username, human_url) VALUES (?,?,?,?,?)',
                        (form["source_link"], short_url, int(form["link_type"]), current_user, ""))
            con.commit()
        else:
            human_url = request.host_url.partition(":5")[0] + f":{client_port}/" + form["human_link"]
            url_cnt = cur.execute("SELECT COUNT(*) FROM urls WHERE human_url = ?", (human_url,)).fetchall()
            if url_cnt[0][0]:
                return jsonify({'msg': "Such attribute is already exists"}), 401
            hash_id = hashlib.sha256(uuid.uuid4().hex.encode() + form["source_link"].encode()).hexdigest()[-HASH_SIZE:]
            short_url = request.host_url.partition(":5")[0] + f":{client_port}/" + hash_id
            con.execute(
                'INSERT INTO urls (original_url, human_url, short_url,  link_type, username)  VALUES (?,?,?,?,?)',
                (form["source_link"], human_url, short_url, int(form["link_type"]), current_user))
            con.commit()
        return jsonify({"short_url": short_url, "attribute": human_url}), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: POST"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/<url_name>/', methods=['POST', "OPTIONS"])
def url_redirect(url_name):
    conn = cur
    session['URL'] = url_name
    form = request.args.to_dict()
    full_url = form['full_url']
    source_url = cur.execute("select original_url from urls where short_url = ? or human_url = ?",
                             (full_url, full_url,)).fetchone()
    if not source_url:
        return jsonify({'msg': "Wrong URL"}), 406
    link_type = cur.execute("select link_type from urls where short_url = ? or human_url = ?",
                            (full_url, full_url,)).fetchone()
    if int(link_type[0]) == 1:
        if source_url[0]:
            original_id = source_url[0]
            clicks = cur.execute("SELECT clicks FROM urls WHERE short_url = ? or human_url = ?",
                                 (full_url, full_url,)).fetchone()
            tmp_click_cnt = clicks[0]
            tmp_click_cnt = tmp_click_cnt + 1
            conn.execute('UPDATE urls SET clicks = ? WHERE short_url = ? or human_url = ?',
                         (tmp_click_cnt, full_url, full_url))
            con.commit()
            return jsonify({"original_id": original_id}), 200
        else:
            return jsonify({'msg': "Unknown URL"}), 404

    if int(link_type[0]) == 2:
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            return jsonify({"msg": "Please, authorize!", "url_name": url_name, "host_url": request.host_url}), 403
        if source_url[0]:
            original_id = source_url[0]
            clicks = cur.execute("SELECT clicks FROM urls WHERE short_url = ? or human_url = ?",
                                 (full_url, full_url,)).fetchone()
            tmp_click_cnt = clicks[0]
            tmp_click_cnt = tmp_click_cnt + 1
            conn.execute('UPDATE urls SET clicks = ? WHERE short_url = ? or human_url = ?',
                         (tmp_click_cnt, full_url, full_url))
            con.commit()
            return jsonify({"original_id": original_id}), 200
        else:
            return jsonify({'msg': "Page not found"}), 404

    if link_type[0] == 3:
        try:
            verify_jwt_in_request()
        except NoAuthorizationError:
            return jsonify("Please, authorize!", {"url_name": url_name, "host_url": request.host_url}), 403
        current_user = get_jwt_identity()
        author = cur.execute("SELECT username FROM urls WHERE short_url = ? or human_url = ? and username = ?",
                             (full_url, full_url, current_user,)).fetchone()
        if not author:
            return jsonify("You have not enough privileges", {"url_name": url_name, "host_url": request.host_url}), 403
        if source_url[0]:
            original_id = source_url[0]
            clicks = cur.execute("SELECT clicks FROM urls WHERE original_url = ? and username = ?",
                                 (original_id, current_user,)).fetchone()
            tmp_click_cnt = clicks[0]
            tmp_click_cnt = tmp_click_cnt + 1
            conn.execute('UPDATE urls SET clicks = ? WHERE short_url = ? or human_url = ?',
                         (tmp_click_cnt, full_url, full_url))
            con.commit()
            return jsonify({"original_id": original_id}), 200
        else:
            return jsonify({'msg': "Page not found"}), 404

    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: POST"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/stats', methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"])
def stats():
    form = request.args.to_dict()
    try:
        verify_jwt_in_request()
    except NoAuthorizationError:
        return jsonify({"msg": "Please, authorize!"}), 403
    current_user = get_jwt_identity()
    if request.method == "GET":
        urls_list = cur.execute('SELECT * FROM urls WHERE username = ?', (current_user,)).fetchall()
        return jsonify({"urls_list": urls_list}), 200
    # edit psydonim
    if request.method == "POST":
        psydo = form["psydo"]
        link_type = form["link_type"]
        edit_id = form['edit_id']
        human_url = psydo
        cur.execute('UPDATE urls SET human_url = ?, link_type = ? WHERE (id = ?) AND (username = ?)',
                    (human_url, link_type, edit_id, current_user,))
        urls_list = cur.execute('SELECT * FROM urls WHERE username = ?', (current_user,)).fetchall()
        con.commit()
        return jsonify({"urls_list": urls_list}), 200

    # delete attribute
    if request.method == "DELETE":
        del_id = form['del_id']
        cur.execute('DELETE FROM urls WHERE id = ? AND username = ?', (del_id, form['username'])).fetchall()
        urls_list = cur.execute('SELECT * FROM urls WHERE username = ?', (form['username'],)).fetchall()
        con.commit()
        return jsonify({"urls_list": urls_list}), 200

    # delete psydonim
    if request.method == "PATCH":
        del_id = form['del_id']
        cur.execute('UPDATE urls SET human_url = "" WHERE id = ? AND username = ?',
                    (del_id, form["username"],)).fetchall()
        urls_list = cur.execute('SELECT * FROM urls WHERE username = ?', (form["username"],)).fetchall()
        con.commit()
        return jsonify({"urls_list": urls_list}), 200

    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET, POST, DELETE, PATCH"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/delete_user/<del_id>', methods=["GET", "DELETE"])
def delete_user(del_id):
    if request.method == "GET":
        return jsonify({'msg': "Access"}), 200
    if request.method == "DELETE":
        cur.execute('DELETE FROM users WHERE id = ?', (del_id,))
        con.commit()
        return jsonify({'msg': "User successfully deleted"}), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET, DELETE"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/about_us', methods=['GET', 'OPTIONS'])
def about():
    if request.method == "GET":
        return jsonify("Access"), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/admin', methods=['GET', "POST", "DELETE", "OPTIONS"])
def admin():
    form = request.args.to_dict()
    if session['username'] != 'Admin':
        return jsonify({'msg': "Login as 'Admin' and try again"})
    urls = cur.execute("SELECT * FROM users")
    if request.method == "GET":
        return jsonify({"urls": urls}), 200
    if request.method == "POST":
        return jsonify({"urls": urls}), 200
    if request.method == "DELETE":
        del_id = form["del_id"]
        username = cur.execute("SELECT username FROM users WHERE id = ?", (del_id,))
        cur.execute('DELETE FROM users WHERE id = ?', (del_id,))
        cur.execute('DELETE FROM urls WHERE username = ?', (username,))
        con.commit()
        return jsonify({"urls": urls}), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET, POST, DELETE"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/free_link', methods=['GET', "POST", 'OPTIONS'])
def free_link():
    session["username"] = "guest"
    form = request.args.to_dict()
    if request.method == "GET":
        return jsonify({'msg': "Enter source link"}), 200
    if request.method == 'POST':
        url = form['source_link']
        data = datetime.datetime.utcnow()-datetime.timedelta(seconds=-20)
        con.execute(f"DELETE FROM urls WHERE created > {data.replace(microsecond=0).timestamp()} "
                    f"AND created < {datetime.datetime.utcnow().replace(microsecond=0).timestamp()}")
        con.commit()
        hash_symbols = 8
        if hash_symbols < 8:
            HASH_SIZE = 8
        else:
            HASH_SIZE = hash_symbols
        hash_id = hashlib.sha256(uuid.uuid4().hex.encode() + url.encode()).hexdigest()[-HASH_SIZE:]
        short_url = request.host_url.partition(":5")[0] + f':{client_port}/' + hash_id
        con.execute('INSERT INTO urls (original_url, short_url,  link_type, username) VALUES (?,?,?,?)',
                    (url, short_url, 1, session["username"]))
        con.commit()
        return jsonify({"short_url": short_url}), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET, DELETE"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


@app.route('/authorize/<url>/', methods=['GET', 'POST', 'OPTIONS'])
def authorize(url):
    form = request.args.to_dict()
    if request.method == 'POST':
        usr_pass = cur.execute("SELECT password FROM users WHERE username = ?", (form['username'],)).fetchone()
        if not usr_pass:
            return jsonify({'msg': "Current user doesn't exists"}), 404
        else:
            if bcrypt.checkpw(form['password'].encode("utf8"), usr_pass[0].encode("utf8")):
                session['username'] = form['username']
                access_token = create_access_token(identity=form['username'],
                                                   expires_delta=datetime.timedelta(seconds=expiration_time))
                redirect_url = request.host_url.partition(":5")[0] + f":{client_port}/" + url
                resp = jsonify({"msg": "Success auth", "redirect_url": redirect_url, "access_token": access_token})
                set_access_cookies(resp, access_token)
                app.config["JWT_COOKIE_CSRF_PROTECT"] = False
                resp.status_code = 200
                return resp
            else:
                return jsonify({'msg': "Wrong password"}), 404
    if request.method == 'GET':
        return jsonify({'msg': "Enter username and password"}), 200
    if request.method == "OPTIONS":
        return jsonify({'msg': "Allow: GET, POST"}), 200
    else:
        jsonify({'msg': "Method Not Allowed"}), 405


if __name__ == "__main__":
    app.run(port=5001)

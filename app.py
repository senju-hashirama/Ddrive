from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    send_file,
    flash,
)
from flask_session import Session
import pyrebase
import json
import subprocess
from werkzeug.utils import secure_filename
import os
import requests
import bcrypt
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask_assets import Bundle, Environment


def encrypting(password, pepper):
    bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    print(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes + pepper.encode("utf-8")))
    hash = salt + "$$".encode() + bcrypt.hashpw(key, salt)
    return key, hash


def verify_hash(hash, passwd):
    print(hash)
    ohash = hash
    salt = hash.split("$$")[0].encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(
        kdf.derive(passwd.encode() + app.secret_key.encode("utf-8"))
    )
    hash = salt + "$$".encode() + bcrypt.hashpw(key, salt)
    print(hash, ohash)
    if hash == ohash.encode():
        return True, key
    else:
        return False, 0


def encrypt_file(filedata, key, filename):

    fernet = Fernet(key)
    encrypted = fernet.encrypt(filedata)

    a = open(os.path.join(app.config["uploadFolder"], filename), "wb")
    a.write(encrypted)
    a.flush()
    a.close()


def decrypt_file(filename, key):
    fernet = Fernet(key)
    encrypted = open(os.path.join(app.config["uploadFolder"], filename), "rb").read()
    decrypted = fernet.decrypt(encrypted)
    a = open(os.path.join(app.config["uploadFolder"], "decrypted" + filename), "wb")
    a.write(decrypted)
    a.flush()
    a.close()


app = Flask(__name__)

# Bundling src/main.css files into dist/main.css'
css = Bundle("src/main.css", output="dist/main.css", filters="postcss")

assets = Environment(app)
assets.register("main_css", css)
css.build()

app.secret_key = "cre=ebrorU#Ipr&b#gibapreyAqlmLwufof+7ipo4uJa@rozi2"
app.config["uploadFolder"] = "uploads"

config = {
    "apiKey": "AIzaSyCzeZb62c_LyBLVSGwMMiVWJ8frHp9dKi4",
    "authDomain": "test-ipfs-8d946.firebaseapp.com",
    "projectId": "test-ipfs-8d946",
    "storageBucket": "test-ipfs-8d946.appspot.com",
    "messagingSenderId": "72753508870",
    "appId": "1:72753508870:web:52d51c4f54bf06a83f4987",
    "databaseURL": "https://test-ipfs-8d946-default-rtdb.asia-southeast1.firebasedatabase.app/",
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
db = firebase.database()


@app.route("/")
def home_page():

    if "UserName" in session:

        return render_template("upload.html")
    else:
        return render_template("login.html")


@app.route("/loginuser")
def login_user():
    return render_template("login.html")


@app.route("/register", methods=["POST"])
def registerUser():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        passwd = request.form.get("password")
        cpasswd = request.form.get("cpassword")
        if "UserID" not in session:

            if "" not in [username, email, passwd, cpasswd]:

                request_ref = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={0}".format(
                    config["apiKey"]
                )
                headers = {"content-type": "application/json; charset=UTF-8"}
                data = json.dumps(
                    {
                        "email": email,
                        "password": passwd,
                        "returnSecureToken": True,
                        "displayName": username,
                    }
                )
                try:
                    request_object = requests.post(
                        request_ref, headers=headers, data=data
                    )
                except:
                    flash("Unable to register you please try again later", "error")
                    return redirect("/registernew")

                out = request_object.json()
                print(out["localId"])
                if "error" in out:
                    flash(out["error"]["message"].replace("_", " "), "error")
                    return redirect("/registernew")
                else:
                    # db.child(session["UserID"])
                    auth.send_email_verification(out["idToken"])
                    db.child(out["localId"]).set("")
                    flash("Please verify email to login", "warning")
                    return redirect("/loginuser")
            else:
                flash("Check if all fields are entered", "warning")
                return redirect("/registernew")
        else:
            flash("You are already registered!!", "warning")
            return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    if (email != "") & (password != ""):

        try:
            user = auth.sign_in_with_email_and_password(email, password)
        except:
            flash("Failed to login check your email and password", "error")
            return redirect("/loginuser")
        UserInfo = auth.get_account_info(user["idToken"])
        session["Verified"] = UserInfo["users"][0]["emailVerified"]
        if session["Verified"]:
            session["UserName"] = user["displayName"]
            session["UserID"] = UserInfo["users"][0]["localId"]
            session["AllowedFiles"] = []

            return redirect("/")
        else:
            flash("Verify email to login")
            return redirect("/loginuser")
    else:
        flash("Check email and password and try again", "error")
        return redirect("/loginuser")


@app.route("/uploadfile")
def uploadf():
    return render_template("upload.html")


@app.route("/upload", methods=["GET", "POST"])
def uploadToServer():
    if request.method == "POST":

        if "UserID" in session:
            users = db.get().val()
            if session["UserID"] in users:
                files = request.files.get("file")
                secretKey = request.form.get("key")
                print(files, secretKey)

                filename = secure_filename(files.filename)
                filedata = files.read()
                key, hash = encrypting(secretKey, app.secret_key)
                print(key, hash)
                encrypt_file(filedata, key, filename)
                a = upload_file(
                    os.path.join(app.config["uploadFolder"] + "/" + filename),
                    hash,
                )

                if not a:
                    flash("File encrypted and uploaded", "message")
                    return redirect("/uploadfile")
                else:
                    flash(a, "error")
                    return redirect("/uploadfile")

            else:
                flash("Do not try shaddy stuff REGISTER to use the website", "error")
                return redirect("/registernew")

        else:
            flash("Login first", "error")
            return redirect("/loginuser")
    else:
        flash("Login first", "error")
        return redirect("/loginuser")


@app.route("/registernew")
def reg():
    return render_template("register.html")


@app.route("/verify", methods=["POST"])
def download():
    if request.method == "POST":
        if "UserID" in session:
            users = db.get().val()
            for i in users:
                print(i, session["UserID"])
            if session["UserID"] in users:

                passwd = request.form.get("password")
                filename = request.form.get("filename").replace(".", ",")

                print("filename", filename)
                print("passwd", passwd)

                try:
                    filedata = (
                        db.child(session["UserID"])
                        .child(filename)
                        .child("data")
                        .get()
                        .val()
                    )
                except:
                    flash("Could not get file try again ", "error")
                    return redirect("/verifyuser")
                print("\n FILEDATA \n")
                print(db.child(session["UserID"]).child(filename))
                if filedata is not None:
                    cid = filedata[-1]
                    shash = filedata[0]
                else:
                    flash("Invalid filename", "error")
                    return redirect("/verifyuser")
                print("cid", cid, shash)
                # shash=db.child(session["UserID"]).child(filename).child("data").get().val()[0]
                check, key = verify_hash(shash, passwd)
                if check:
                    file = filename.replace(",", ".")
                    session["AllowedFiles"].append(file)
                    opp = subprocess.run(
                        "w3 get {} -o {}".format(cid, app.config["uploadFolder"]),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=True,
                    )
                    if opp.returncode == 0:

                        decrypt_file(file, key)
                        file = "decrypted" + filename.replace(",", ".")
                        return send_file("uploads/{}".format(file), as_attachment=True)
                    else:
                        flash("Unable to fetch your file please try later", "error")
                        return redirect("/verifyuser")
                else:
                    flash("wrong password", "error")
                    return redirect("/verifyuser")

            else:
                flash("Do not try shaddy stuff REGISTER to use the website", "error")
                return redirect("/registernew")


@app.route("/delete", methods=["POST"])
def delete():
    if request.method == "POST":
        if "UserID" in session:
            users = db.get().val()
            for i in users:
                print(i, session["UserID"])
            if session["UserID"] in users:

                passwd = request.form.get("password")
                filename = request.form.get("filename").replace(".", ",")

                try:
                    filedata = (
                        db.child(session["UserID"])
                        .child(filename)
                        .child("data")
                        .get()
                        .val()
                    )
                except:
                    flash("Could not get file try again ", "error")
                    return redirect("/verifyuser")
                if filedata is not None:

                    cid = filedata[-1]
                    shash = filedata[0]
                else:
                    flash("Invalid filename", "error")
                    return redirect("/verifyuser")
                print("cid", cid, shash)
                # shash=db.child(session["UserID"]).child(filename).child("data").get().val()[0]
                check, key = verify_hash(shash, passwd)
                if check:
                    file = filename.replace(",", ".")
                    db.child(session["UserID"]).child(filename).remove()
                    flash("File deleted", "message")
                    return redirect("/verifyuser")
                else:
                    flash("wrong password", "error")
                    return redirect("/verifyuser")

            else:
                flash("Do not try shaddy stuff REGISTER to use the website", "error")
                return redirect("/registernew")


@app.route("/logout")
def logout():
    if "UserID" in session:
        try:
            d = db.child(session["UserID"]).get().val()
            if d is None:
                flash("Login first", "error")
                return redirect("/loginuser")
        except:
            flash("Register first", "error")
            return "/registernew"
        for i in d:
            i = i.replace(",", ".")
            if os.path.exists(os.path.join(app.config["uploadFolder"], i)):
                os.remove(os.path.join(app.config["uploadFolder"], i))

            if os.path.exists(
                os.path.join(app.config["uploadFolder"], "decrypted" + i)
            ):
                os.remove(os.path.join(app.config["uploadFolder"], "decrypted" + i))
        session.pop("UserID", None)

        session.pop("UserName", None)
        return redirect("/")
    else:
        flash("Login first", "error")
        return redirect("/loginuser")


@app.route("/download", methods=["POST", "GET"])
def send_download():
    if request.method == "POST":
        if "UserID" in session:
            users = db.get().val()

            if session["UserID"] in users:
                file = request.form.get("filename")

                if os.path.exists(os.path.join(app.config["uploadFolder"], file)):

                    return send_file(
                        os.path.join(app.config["uploadFolder"], file),
                        as_attachment=True,
                        attachment_filename=file,
                    )
                else:
                    try:
                        cid = (
                            db.child(session["UserID"])
                            .child(file.replace(".", ","))
                            .child("data")
                            .get()
                            .val()[-1]
                        )
                    except:
                        flash("Invalid file", "error")
                        return redirect("/verifyuser")
                    os.system("w3 get {} -o {}".format(cid, app.config["uploadFolder"]))

                    return send_file(
                        os.path.join(app.config["uploadFolder"], file),
                        as_attachment=True,
                        attachment_filename=file,
                    )
            else:
                flash("Do not try shaddy stuff REGISTER to use the website", "error")
                return redirect("/registernew")

        else:
            flash("Login first", "error")
            return redirect("/loginuser")


@app.route("/verifyuser")
def verify():
    if "UserID" in session:
        print(session)
        users = db.get().val()
        if session["UserID"] in users:
            d = db.child(session["UserID"]).get().val()
            print(d)
            lis = {}
            c = 0
            for i in d:
                lis[c] = i.replace(",", ".")
                c = c + 1

            return render_template("verify.html", files=lis)
        else:
            flash("Upload a file first", "warning")
            return redirect("/uploadfile")
    else:
        flash("Login first", "error")
        return redirect("/loginuser")


@app.route("/files", methods=["GET"])
def getFiles():
    if request.method == "GET":
        if "UserID" in session:
            users = db.get().val()
            print(db.get().val())

            if session["UserID"] in users:
                try:

                    d = db.child(session["UserID"]).get().val()
                    print(d)
                except:
                    flash(
                        "Could not find files related to {}".format(
                            session["UserName"]
                        ),
                        "error",
                    )
                    return redirect("/")

                lis = {}
                c = 0
                for i in d:
                    lis[c] = i.replace(",", ".")
                    c = c + 1
                return lis
            else:
                flash("Do not try shaddy stuff REGISTER to use the website", "error")
                return redirect("/registernew")
        else:
            flash("Login first", "error")
            return redirect("/loginuser")


def upload_file(file, hash):
    opp = subprocess.run(
        f"w3 put {file}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )
    print("opp", opp.stderr)
    if opp.returncode == 0:
        filename = file.split("uploads/")[-1].replace(".", ",")
        print("filename", filename)
        filecid = opp.stdout.decode().split()[1]
        print(filename, filecid)
        data = {"data": [hash.decode(), filecid]}
        db.child(session["UserID"]).child(filename).set(data)
    else:
        return "Unable to upload your file"


if __name__ == "__main__":
    app.run(debug=True)

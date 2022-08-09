
from flask import Flask,render_template,request,session,redirect,url_for,send_file
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

def encrypting(password, pepper):
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    print(salt)
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes+pepper.encode('utf-8')))
    hash =salt+"$$".encode()+bcrypt.hashpw(key,salt)
    return key, hash

def verify_hash(hash,passwd):
    ohash=hash
    salt=hash.split("$$")[0].encode()
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd.encode()+app.secret_key.encode('utf-8')))
    hash =salt+"$$".encode()+bcrypt.hashpw(key,salt)
    print(hash,ohash)
    if hash==ohash.encode():
        return True,key
    else:
        return False,0

def encrypt_file(filedata,key,filename):

    fernet=Fernet(key)
    encrypted=fernet.encrypt(filedata)

    a=open(os.path.join(app.config["uploadFolder"],filename),"wb")
    a.write(encrypted)
    a.flush()
    a.close()

def decrypt_file(filename,key):
    fernet=Fernet(key)
    encrypted=open(os.path.join(app.config["uploadFolder"],filename),"rb").read()
    decrypted=fernet.decrypt(encrypted)
    a=open(os.path.join(app.config["uploadFolder"],"decrypted"+filename),"wb")
    a.write(decrypted)
    a.flush()
    a.close()


app=Flask(__name__)

app.secret_key=("cre=ebrorU#Ipr&b#gibapreyAqlmLwufof+7ipo4uJa@rozi2")
app.config["uploadFolder"]=r"C:\Users\monish\Desktop\hackofest\UploadFiles"
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]="filesystem"
Session(app)
config={
   "apiKey":"AIzaSyCzeZb62c_LyBLVSGwMMiVWJ8frHp9dKi4",
    "authDomain":"test-ipfs-8d946.firebaseapp.com",
    "projectId":"test-ipfs-8d946",
    "storageBucket":"test-ipfs-8d946.appspot.com",
    "messagingSenderId":"72753508870",
    "appId":"1:72753508870:web:52d51c4f54bf06a83f4987",
    "databaseURL":"https://test-ipfs-8d946-default-rtdb.asia-southeast1.firebasedatabase.app/"
}

firebase=pyrebase.initialize_app(config)
auth=firebase.auth()
db=firebase.database()

@app.route("/")
def home_page():
    
    if "UserName" in session:
            
            return render_template("upload.html")
    else:
        return render_template("login.html")


@app.route("/register",methods=["POST"])
def registerUser():
    if request.method=="POST":
        username=request.form.get("username")
        email=request.form.get("email")
        passwd=request.form.get("password")
        cpasswd=request.form.get("cpassword")

        request_ref = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={0}".format(config["apiKey"])
        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"email": email, "password": passwd, "returnSecureToken": True,"displayName":username})

        request_object = requests.post(request_ref, headers=headers, data=data)
        out=request_object.json()
        auth.send_email_verification(out["idToken"])

        return redirect("/")


@app.route("/login",methods=["POST"])
def login():
        email=request.form.get("email")
        password=request.form.get("password")
        try:
            user=auth.sign_in_with_email_and_password(email,password)
        except:
            return "failed to login"
        UserInfo=auth.get_account_info(user["idToken"])
        session["Verified"]=UserInfo["users"][0]["emailVerified"]
        if session["Verified"]:    
                session["UserName"]=user["displayName"]
                session["UserID"]=UserInfo["users"][0]["localId"]
                session["AllowedFiles"]=[]
                
                return redirect("/")
        else:
            return "verify email"

        

@app.route("/upload",methods=['GET', 'POST'])
def uploadToServer():
    if request.method=="POST":
        for i in session:
            print(i)
        if "UserID" in session:
                    
                files=request.files.get("file")

                secretKey=request.form.get("key")
                
                
                filename=secure_filename(files.filename)
                filedata=files.read()
                key,hash=encrypting(secretKey,app.secret_key)
                print(key,hash)
                encrypt_file(filedata,key,filename)

                

                
                #files.save(os.path.join(r"C:\Users\monish\Desktop\hackofest\UploadFiles",filename))
                #file.append(os.path.join(r"C:\Users\monish\Desktop\hackofest\UploadFiles",filename))
                
                upload_file(os.path.join(r"C:\Users\monish\Desktop\hackofest\UploadFiles",filename),hash)


                return redirect("/verifyuser")
        else:
            return "login first"

@app.route("/registernew")
def reg():
    return render_template("register.html")
@app.route("/verify",methods=["POST"])
def download():
    if request.method=="POST":
                
            passwd=request.form.get("password")
            filename=request.form.get("filename").replace(".",",")
            
            
            users=db.get().val()
            if session["UserID"] in users:

                cid=db.child(session["UserID"]).child(filename).child("data").get().val()[-1]
                shash=db.child(session["UserID"]).child(filename).child("data").get().val()[0]
                check,key=verify_hash(shash,passwd)
                if check:
                    file=filename.replace(",",".")
                    session["AllowedFiles"].append(file)
                    os.system("w3 get {} -o {}".format(cid,app.config["uploadFolder"]))
                    decrypt_file(file,key)
                    file="decrypted"+filename.replace(",",".")
                    return send_file("UploadFiles\\{}".format(file),as_attachment=True)
                else:
                    return "not verified"
            else:
                return "login first"
@app.route("/logout")
def logout():
    if "UserID" in session:
            d=db.child(session["UserID"]).get().val()
            for i in d:
                i=i.replace(",",".")
                if os.path.exists(os.path.join(app.config["uploadFolder"],i)):
                        os.remove(os.path.join(app.config["uploadFolder"],i))
                
                if os.path.exists(os.path.join(app.config["uploadFolder"],"decrypted"+i)):
                        os.remove(os.path.join(app.config["uploadFolder"],"decrypted"+i))
            session.pop("UserID",None)

            session.pop("UserName",None)
            return redirect("/")
    else:
        return "login first"


@app.route("/download/<file>", methods=["POST", "GET"])
def send_download(file):
    if request.method == "GET":
        if "UserID" in session:
                if file in session["AllowedFiles"]:
                            
                        
                        return send_file(
                            os.path.join(app.config["uploadFolder"] , "decrypted" + file),
                            as_attachment=True,
                            attachment_filename=file,
                        )
                else:
                    return {"status":400}
        else:
            return {"status":400}
@app.route("/verifyuser")
def verify():
    if "UserID" in session:
            d=db.child(session["UserID"]).get().val()
            lis={}
            c=0
            for i in d:
                lis[c]=i.replace(",",".")
                c=c+1

            return render_template("verify.html",files=lis)
    else:
        return "login firts"

@app.route("/files",methods=["GET"])
def getFiles():
    if request.method=="GET":
        if "UserID" in session:
                
            d=db.child(session["UserID"]).get().val()
            lis={}
            c=0
            for i in d:
                lis[c]=i.replace(",",".")
                c=c+1
            return lis
        else:
            return "login first"

def upload_file(file,hash):
    if "UserID" in session:
                users=db.get().val()
 
              
                opp=subprocess.run(["w3","put" ,file],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
                filename=file.split("\\")[-1].replace(".",",")
                filecid=opp.stdout.decode().split()[1]
                print(filename,filecid)
                data={
                                "data":[hash.decode(),filecid]
                            }
                db.child(session["UserID"]).child(filename).set(data)
    else:
        return "login first"
                

if __name__=="__main__":
    app.run()

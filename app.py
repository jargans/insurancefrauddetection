from pickletools import uint8
from re import I
from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt
import pickle
#set app as a Flask instance 
app = Flask(__name__)
#encryption relies on secret keys so they could be run
app.secret_key = "testing"
#connoct to your Mongo DB database
client = pymongo.MongoClient("mongodb+srv://rishabh:rishu@cluster0.idy05.mongodb.net/?retryWrites=true&w=majority")

#get the database name
db = client.get_database('mongologinexample')
#get the particular collection that contains the data
records = db.register

#assign URLs to have a particular route 
@app.route('/', methods=['GET', 'POST'])
def homepage():
    return render_template('homepage.html')
@app.route("/register", methods=['post', 'get'])
def index():
    message = ''
    #if method post in index
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == 'POST':
        user = request.form.get("fullname")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        #if found in database showcase that it's found 
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            #hash the password and encode it
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            #assing them in a dictionary in key value pairs
            user_input = {'name': user, 'email': email, 'password': hashed}
            #insert it in the record collection
            records.insert_one(user_input)
            
            #find the new created account and its email
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            #if registered redirect to logged in as the registered user
            return render_template('logged_in.html', email=new_email)
    return render_template('index.html')



@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        #check if email exists in database
        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
            #encode the password and check if it matches
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)

@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return render_template('logged_in.html', email=email)
    else:
        return redirect(url_for("login"))
@app.route('/predict',methods=['POST','GET']) # route to show the predictions in a web UI
def result():
    if request.method == 'POST':
        try:
            #  reading the inputs given by the user
            nm=request.form['nm']
            app=request.form['app']
            el=request.form['el']
            mg=request.form['mg']
            ml=request.form['ml']
            time=request.form['time']
            nvi=request.form['nvi']
            nbi=request.form['nbi']
            nwp=request.form['nwp']
            aci=request.form['aci']
            acp=request.form['acp']
            acv=request.form['acv']
            pcsl=request.form['pcsl']
            if (pcsl=="0"):
                p_csl=0
            if (pcsl=="2.5"):
                p_csl=2.5
            if (pcsl=="5"):
                p_csl=5
            gender=request.form['g']
            if (gender=='M'):
                gn=1
            if (gender=='F'):
                gn=0
            heq=request.form['eq']
            if (heq=='jd'):
                eql=1
            if (heq=='hs'):
                eql=2
            if (heq=='coll'):
                eql=3
            if (heq=='mas'):
                eql=4
            if (heq=='assc'):
                eql=5
            if (heq=='md'):
                eql=6
            if (heq=='phd'):
                eql=7
            ins=request.form['ins']
            if (ins=='td'):
                insvr=1
            if (ins=='md'):
                insvr=2
            if (ins=='majd'):
                insvr=3
            if (ins=='tl'):
                insvr=4
            pd=request.form['pd']
            if (pd=='Y'):
                prd=1
            if (pd=='N'):
                prd=0
            pr=request.form['pr']
            if (pr=="1"):
                polr=1
            if (pr=="0"):
                polr=0
            occu=request.form['occu']
            if (occu=='af'):
                armedforces=1           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='cr'):
                armedforces=0           
                craftrepair=1           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='em'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=1        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='ff'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=1        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='hc'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=1      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='moi'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=1      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='os'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=1          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='phs'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=1        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='ps'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=1         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='prs'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=1        
                sales=0                  
                techsupport=0           
                transportmoving=0
            if (occu=='s'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=1                  
                techsupport=0           
                transportmoving=0
            if (occu=='ts'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=1           
                transportmoving=0
            if (occu=='tm'):
                armedforces=0           
                craftrepair=0           
                execmanagerial=0        
                farmingfishing=0        
                handlerscleaners=0      
                machineopinspct=0      
                otherservice=0          
                privhouseserv=0        
                profspecialty=0         
                protectiveserv=0        
                sales=0                  
                techsupport=0           
                transportmoving=1
            dph=request.form['dph']
            if(dph=='nif'):
                notinfamily=1           
                otherrelative=0     
                ownchild=0            
                unmarried=0            
                wife=0
            if(dph=='or'):
                notinfamily=0           
                otherrelative=1     
                ownchild=0            
                unmarried=0            
                wife=0    
            if(dph=='oc'):
                notinfamily=0           
                otherrelative=0     
                ownchild=1            
                unmarried=0            
                wife=0  
            if(dph=='um'):
                notinfamily=0           
                otherrelative=0     
                ownchild=0            
                unmarried=1            
                wife=0
            if(dph=='w'):
                notinfamily=0           
                otherrelative=0     
                ownchild=0            
                unmarried=0            
                wife=1
            it=request.form['it']
            if (it=='pc'):
                pc=1
                svc=0
                vt=0
            if (it=='svc'):
                pc=0
                svc=1
                vt=0
            if (it=='vt'):
                pc=0
                svc=0
                vt=1
            ct=request.form['ct']
            if (ct=='rc'):
                rc=1
                sc=0
            if (ct=='sc'):
                rc=0
                sc=1
            ac=request.form['ac']
            if (ac=='fire'):
                fire=1
                none=0
                other=0
                police=0
            if (ac=='none1'):
                fire=0
                none=1
                other=0
                police=0
            if (ac=='other'):
                fire=0
                none=0
                other=1
                police=0
            if (ac=='police'):
                fire=0
                none=0
                other=0
                police=1
            filename = 'rf_model.pkl'
            loaded_model = pickle.load(open(filename, 'rb')) # loading the model file from the storage
            #predictions using the loaded model file
            prediction=loaded_model.predict([[nm,app,el,mg,ml,time,nvi,nbi,nwp,aci,
            acp,acv,p_csl,gn,eql,insvr,prd,polr,armedforces,craftrepair,
            execmanagerial,farmingfishing,handlerscleaners,machineopinspct,
            otherservice,privhouseserv,profspecialty,protectiveserv,sales,
            techsupport,transportmoving,notinfamily,otherrelative,
            ownchild,unmarried,wife,pc,svc,vt,rc,sc,fire,none,other,police]])
            print('prediction is', prediction)
            if prediction[0]==1:
                prediction="Fraud"
                elligible="Not Elligible"
            else:
                prediction="not Fraud"
                elligible="Elligible"
            # showing the prediction results in a UI
            return render_template('results.html',prediction=prediction,elligible=elligible)
        except Exception as e:
            print('The Exception message is: ',e)
           
    # return render_template('results.html')
    else:
            return render_template('homepage.html') 
@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("signout.html")
    else:
        return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)

 
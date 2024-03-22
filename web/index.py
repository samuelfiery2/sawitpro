

from flask import Flask, render_template, request, redirect, url_for, flash,session,app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required,current_user
from werkzeug.utils import secure_filename

import os
from datetime import timedelta
import dotenv
from passlib.hash import sha256_crypt


dotenv.load_dotenv()
secret = str(os.environ.get('secret'))

db_user = str(os.environ.get('db_user'))
db_pass = str(os.environ.get('db_pass'))
db_path = str(os.environ.get('db_path'))

app = Flask(__name__, template_folder='../templates')
app.config['SECRET_KEY'] = secret
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://{}:{}@{}/public".format(db_user, db_pass, db_path)
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=5)
app.config['UPLOAD_FOLDER'] = 'static'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Maximum file size (2 MB)
basedir = os.path.abspath(os.path.dirname(__file__))


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.app_context().push()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    image_path = db.Column(db.String(255))  # Store image path

    def set_password(self, password):
        self.password_hash = sha256_crypt.hash(password)

    def check_password(self, password):
        return sha256_crypt.verify(password, self.password_hash)
class Detail(db.Model):
    id = db.Column(db.Integer)
    image_path = db.Column(db.String(255))
    placeholder = db.Column(db.Integer, primary_key=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            print(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    
    if request.method == 'POST' and 'image' in request.files:
        files = request.files.getlist('image')
        for file in files:
            if file.filename == '':
                flash('No selected file!', 'error')
            elif file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = (os.path.join(basedir,app.config['UPLOAD_FOLDER'], filename))
                file.save(file_path)
                new_detail = Detail(id=current_user.id,image_path=filename)
               
                db.session.add(new_detail)
                db.session.commit()
                flash('File uploaded successfully!', 'success')

            else:
                flash('Invalid file format!', 'error')
   
    user_images = Detail.query.filter_by(id=current_user.id).all()
    return render_template('dashboard.html', user_images=user_images)
   

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# Function to check if file extension is allowed
def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions






if __name__ == "__main__":
    #db.create_all()
    app.run(host="127.0.0.1", port=8000, debug=True)

    
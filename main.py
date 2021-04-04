from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        submitted_email = request.values.get("email")
        user_object = db.session.query(User).filter(User.email == submitted_email).first()

        if user_object is None:
            new_user = User(
                email=submitted_email,
                password=generate_password_hash(password=request.values.get("password"),
                                                method="pbkdf2:sha256", salt_length=8),
                name=request.values.get("name")
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect("/secrets")
        else:
            flash("Error: This email already exists login instead")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.values.get("email")
        password = request.values.get("password")

        user_object = db.session.query(User).filter(User.email == email).first()
        if user_object is not None:
            check_password = check_password_hash(pwhash=user_object.password, password=password)
            if check_password:
                login_user(user_object)
                return redirect("/secrets")
            else:
                flash("Error: Incorrect password please try again")
        else:
            flash("Error: This email does not exist")

        return render_template("login.html")

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    username = current_user.name
    return render_template("secrets.html", name=username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Successfully Logged Out")
    return redirect("/")


@app.route('/download')
@login_required
def download():
    return send_from_directory(filename="cheat_sheet.pdf", directory="static/files/")


if __name__ == "__main__":
    app.run(debug=True)

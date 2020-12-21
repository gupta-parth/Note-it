from flask import Flask
from flask import flash, redirect, render_template, session, request, jsonify, make_response, url_for
from flask_session import Session
from tempfile import mkdtemp
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)

app.config["SECRET_KEY"] = b'^\xa8\xeb\x83\xaa\xfb\xa6\x06\x16\xc5\x94\x10\xaf\x1c\xf5'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Database
db = SQLAlchemy(app)

# Models 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    notes = db.relationship("Note", backref="creator", lazy=True)

    def __repr__(self):
        return f"User('{self.username}')"


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20))
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self):
        return f"Note('{self.title}', '{self.date_created}')"


def login_required(f):
    """
    Decorate routes to require login.
    
    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# Home page of the website
@app.route("/")
@login_required
def index():
    return render_template("index.html")


# Registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Error checking if the user does not enter information properly
        if not username:
            return render_template("apology.html", message="Make sure to enter a username"), 403
        elif not password:
            return render_template("apology.html", message="Make sure to enter a password"), 403
        elif not confirmation:
            return render_template("apology.html", message="Make sure to re-enter password"), 403
        elif password != confirmation:
            return render_template("apology.html", message="Passwords don't match"), 403

        existing_users = User.query.filter_by(username=username).all()
        if existing_users:
            return render_template("apology.html", message="Username already taken"), 403
        
        # Adding the user to database
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash("Successfully registered!")
        user = User.query.filter_by(username=username).first()  # Get that user
        session["user_id"] = user.id  # Remember the user 
        return redirect("/notes")
    
    # GET request
    else:
        return render_template("register.html")


# Login page 
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Error checking if the user does not enter information properly
        if not username:
            return render_template("apology.html", message="Make sure to enter a username"), 403
        elif not password:
            return render_template("apology.html", message="Make sure to enter a password"), 403

        # Query the database
        user = User.query.filter_by(username=username).first()
        
        # Authentication
        if not user:
            return render_template("apology.html", message="User not found"), 403
        elif not check_password_hash(user.password_hash, password):
            return render_template("apology.html", message="Invalid password"), 403

        session["user_id"] = user.id  # Remember the user 
        return redirect("/")

    # GET request
    else:
        return render_template("login.html")


# Notes page
@app.route("/notes")
@login_required
def notes():
    """
    Shows the notes for the user
    """

    # Get the notes for the user who's currently logged in 
    notes = Note.query.filter_by(user_id=session["user_id"]).all()

    return render_template("notes.html",notes=notes)


@app.route("/notes/add-note", methods=["POST"])
@login_required
def add_note():
    """
    Adds a new note
    """
    # Get the note 
    new_note = request.get_json(force=True)

    # Add note to database
    note = Note(title=new_note["title"], content=new_note["content"], user_id=session["user_id"])

    db.session.add(note)
    db.session.commit()
    return redirect("/notes")


@app.route("/notes/delete-note", methods=["POST"])
def delete_note():
    """
    Deletes a note
    """
    note_id = request.form.get("note-id")
    note = Note.query.filter_by(id=note_id).first()
    db.session.delete(note)
    db.session.commit()

    return redirect("/notes")


@app.route("/contact", methods=["GET", "POST"])
@login_required
def contact():
    """
    Writes the user message to a local file in the directory
    """
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")

        with open("messages.txt", "a") as messageFile:
            messageFile.write(f"Message by {name}\n")
            messageFile.write(f"User email: {email}\n")
            messageFile.write(f"User message: {message}\n")
            messageFile.write("\n")

        flash("Your message has been sent!")
        return redirect("/contact")
        
    else:
        return render_template("contact.html")



@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")



if __name__ == "__main__":
    app.run()


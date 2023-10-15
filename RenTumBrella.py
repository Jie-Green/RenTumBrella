from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin

# Initialization
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///rentumbrella.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "your_unique_secret_key_here"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# Models
class Umbrella(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    design = db.Column(db.String(80), unique=True, nullable=False)
    stock = db.Column(db.Integer, nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route("/")
def index():
    umbrellas = Umbrella.query.all()
    return render_template("index.html", umbrellas=umbrellas)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists. Choose a different one.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password, method="sha256")
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user, remember=True)
            return redirect(url_for("index"))
        else:
            flash("Incorrect username or password")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/catalog")
def catalog():
    umbrellas = Umbrella.query.all()
    return render_template("catalog.html", umbrellas=umbrellas)


@app.route("/rent_umbrella/<int:umbrella_id>")
@login_required
def rent_umbrella(umbrella_id):
    umbrella = Umbrella.query.get_or_404(umbrella_id)

    if umbrella.stock <= 0:
        flash("This umbrella is not available right now.")
        return redirect(url_for("catalog"))

    umbrella.stock -= 1
    db.session.commit()

    flash(f"You have rented the {umbrella.design} umbrella.")
    return redirect(url_for("index"))


@app.route("/return_umbrella/<int:umbrella_id>")
@login_required
def return_umbrella(umbrella_id):
    umbrella = Umbrella.query.get_or_404(umbrella_id)

    umbrella.stock += 1
    db.session.commit()

    flash(f"You have returned the {umbrella.design} umbrella.")
    return redirect(url_for("index"))


@app.route("/add_umbrella", methods=["GET", "POST"])
@login_required  # このアクションを実行するにはログインが必要です。
def add_umbrella():
    if request.method == "POST":
        design = request.form.get("design")
        stock = request.form.get("stock")
        new_umbrella = Umbrella(design=design, stock=stock)
        db.session.add(new_umbrella)
        db.session.commit()
        flash("新しい傘が追加されました。")
        return redirect(url_for("index"))

    return render_template("add_umbrella.html")


@app.route("/delete_umbrella/<int:umbrella_id>", methods=["GET", "POST"])
@login_required
def delete_umbrella(umbrella_id):
    umbrella = Umbrella.query.get_or_404(umbrella_id)

    if request.method == "POST":
        db.session.delete(umbrella)
        db.session.commit()
        flash(f"{umbrella.design}傘が削除されました。")
        return redirect(url_for("catalog"))

    return render_template("delete_umbrella.html", umbrella=umbrella)


# Main execution
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

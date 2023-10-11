from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Umbrella(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    stock = db.Column(db.Integer, default=0)

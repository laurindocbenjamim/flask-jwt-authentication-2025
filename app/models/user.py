
from app.configs import db
from werkzeug.security import check_password_hash



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    full_name = db.Column(db.Text, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    type_of_user = db.Column(db.String(30), nullable=True)

    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)   
     
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "password": self.password_hash,
            "full_name": self.full_name,
        }

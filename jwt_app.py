

import sqlalchemy, os
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from app.utils import db
from flask_migrate import Migrate
from app.models import User, TokenBlocklist
from app import create_app

#from app.models import User
from werkzeug.security import generate_password_hash


app = create_app()
# This function is used to migrate the database
Migrate(app, db)
    
 # Init the db
db.init_app(app)

if __name__ == '__main__':

    with app.app_context():
        db.create_all()
        try:
            #db.session.add(User(firstname="Bruce", lastname="Wayne", username="batman", email="batman@datatuning.pt", confirmed=True, password_hash=generate_password_hash(""),type_of_user="Basic"))
            #db.session.add(User(firstname="Ann", lastname="Takamaki", username="panther", email="panther@datatuning.pt", confirmed=True, password_hash=generate_password_hash(""),type_of_user="Admin"))
            #db.session.add(User(firstname="Jester", lastname="Lavore", username="little_sapphire", email="little_sapphire@datatuning.pt", confirmed=True, password_hash=generate_password_hash(""),type_of_user="Basic"))
            #db.session.commit()

            #now = datetime.now(timezone.utc)
            #db.session.add(TokenBlocklist(jti='jti', created_at=now))
            #db.session.commit()
            """print("\n\n => FLASK_ENV:___")
            print(os.getenv("FLASK_ENV", "testting"))

            print("\n\n => DATABASE_URL:___")
            print(os.getenv("DATABASE_URL", "sqlite://"))

            print("\n\n => RATE_LIMIT:___")
            print(os.getenv("RATE_LIMIT", "100 per day,10 per minute"))

            print("\n\n => JWT_COOKIE_DOMAIN:___")
            print(app.config['JWT_COOKIE_DOMAIN'])

            print("\n\n => JWT_COOKIE_SAMESITE:___")
            print(app.config['JWT_COOKIE_SAMESITE'])

            print("\n\n => JWT_COOKIE_SECURE:___")
            print(app.config['JWT_COOKIE_SECURE']) 

            print("\n\n => JWT_SECRET_KEY:___")
            print(app.config['JWT_SECRET_KEY']) """

        except sqlalchemy.exc.IntegrityError as e:
            db.session.rollback()
            print(f"\n\n => This user already exists. \nError: {str(e)}")
        except Exception as e:
            db.session.rollback()
            print(f"\n\n => Exception: {str(e)}")
        finally:
            print('\n\n => DB Query processed!')
            try:
                revoked_tokens = TokenBlocklist.query.all()
                users = User.query.all()
                print("\n\n ======> USERS LIST <======")
                for user in users:
                    print(user.to_dict())
                
                print('\n\n =====> REVOKED JWT Tokens <=====')
                #for token in revoked_tokens:
                #    print(token)
                print('\n\n')
                #print(f"CORS-ORIGIN: {app.config['CORS_ORIGIN']}")
            except Exception as e:
                print(f"Error to get Users. {str(e)}")

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['AUDIOBOOKS_FOLDER'], exist_ok=True)
    #app.run(debug=app.config['DEBUG'], port=app.config['PORT'])

    # Run the Flask app with SSL context for HTTPS
    app.run(host="0.0.0.0", 
            ssl_context=('0.0.0.0+4.pem', '0.0.0.0+4-key.pem'), 
            debug=app.config['DEBUG'], 
            port=8443) # Use port 8443 for HTTPS
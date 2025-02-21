

import sqlalchemy
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from app.configs import db
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
            db.session.add(User(full_name="Bruce Wayne", username="batman", email="batman@datatuning.pt", password_hash=generate_password_hash("1234"),type_of_user="Basic"))
            db.session.add(User(full_name="Ann Takamaki", username="panther", email="panther@datatuning.pt", password_hash=generate_password_hash("1234"),type_of_user="Admin"))
            db.session.add(User(full_name="Jester Lavore", username="little_sapphire", email="little_sapphire@datatuning.pt", password_hash=generate_password_hash("1234"),type_of_user="Basic"))
            db.session.commit()

            now = datetime.now(timezone.utc)
            db.session.add(TokenBlocklist(jti='jti', created_at=now))
            db.session.commit()

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
                #for user in users:
                #    print(user.to_dict())
                
                print('\n\n =====> REVOKED JWT Tokens <=====')
                #for token in revoked_tokens:
                #    print(token)
                print('\n\n')
                #print(f"CORS-ORIGIN: {app.config['CORS_ORIGIN']}")
            except Exception as e:
                print(f"Error to get Users. {str(e)}")


    app.run(debug=app.config['DEBUG'], port=app.config['PORT'])
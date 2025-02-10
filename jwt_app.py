

import sqlalchemy
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from app.config import db
from app.models import User, TokenBlocklist
from app import create_app
#from app.models import User
from werkzeug.security import generate_password_hash

app = create_app()

if __name__ == '__main__':

    db.init_app(app)

    with app.app_context():
        db.create_all()
        try:
            db.session.add(User(full_name="Bruce Wayne", username="batman", password_hash=generate_password_hash("1234")))
            db.session.add(User(full_name="Ann Takamaki", username="panther", password_hash=generate_password_hash("1234")))
            db.session.add(User(full_name="Jester Lavore", username="little_sapphire", password_hash=generate_password_hash("1234")))
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
                for user in users:
                    print(user.to_dict())
                
                print('\n\n =====> REVOKED JWT Tokens <=====')
                for token in revoked_tokens:
                    print(token)
                print('\n\n')
            except Exception as e:
                print(f"Error to get Users. {str(e)}")


    app.run(host='0.0.0.0', debug=True, port=5000)
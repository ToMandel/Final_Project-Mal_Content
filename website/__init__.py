from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv, find_dotenv
import os
from flask_login import LoginManager
from mongoengine import connect
from .models import User

load_dotenv(find_dotenv())
password = os.environ.get("MONGODB_PWD")

if not password:
    raise Exception("MONGODB_PWD not found in environment variables")

connection_string = f"mongodb://localhost:27017/MalCont_DB"
# connection_string = f"mongodb+srv://ToMandel:{password}@malcont.buw02kc.mongodb.net/MalCont_DB?retryWrites=true&w=majority"

def create_app():
    app = Flask(__name__)
    CORS(app)  # Enable CORS for all routes
    app.config['SECRET_KEY'] = password

    # Connect MongoEngine to your MongoDB and specify the database name
    connect(host=connection_string)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.objects(id=user_id).first()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_ldap3_login import LDAP3LoginManager
from flask_toastr import Toastr
from hashids import Hashids
from flask_dropzone import Dropzone

app = Flask(__name__)
app.config.from_pyfile('config.py')

ldap = LDAP3LoginManager(app)

db = SQLAlchemy(app)

toastr = Toastr(app)

dropzone = Dropzone(app)
hashids = Hashids(min_length=64, salt=app.config['SECRET_KEY'])

from views import *

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)

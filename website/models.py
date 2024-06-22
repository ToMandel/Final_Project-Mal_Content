import datetime
from flask_login import UserMixin
from mongoengine import Document, StringField, ReferenceField, DateTimeField, ListField

class Report(Document):
    meta = {'collection': 'reports'}
    data = StringField(max_length=1000)
    date = DateTimeField(default=datetime.datetime.now)
    #TODO: add status field of enum type
    user_id = ReferenceField('User')

class User(Document, UserMixin):
    meta = {'collection': 'users'}
    email = StringField(max_length=150, unique=True)
    role = StringField(max_length=150)
    password = StringField(max_length=500)
    first_name = StringField(max_length=150)
    # reports = ListField(ReferenceField(Report), default=[])

class Rule(Document):
    meta = {'collection': 'rules'}
    data = StringField(max_length=1000)
    insertion_time = DateTimeField(default=datetime.datetime.now)
    user_id = ReferenceField('User')
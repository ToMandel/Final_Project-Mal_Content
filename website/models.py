import datetime
from flask_login import UserMixin
from mongoengine import Document, StringField, ReferenceField, DateTimeField, IntField

class RuleType:
    KEYWORD = "keyword"
    PHRASE = "phrase"
    CONTEXTUAL = "contextual"

class ReportType:
    TOXIC = "toxic"
    NON_TOXIC = "non-toxic"

class Report(Document):
    meta = {'collection': 'reports'}
    data = StringField(max_length=500)
    report_type = StringField(max_length=20, options=[ReportType.TOXIC, ReportType.NON_TOXIC])
    date = DateTimeField(default=datetime.datetime.now)
    user_id = ReferenceField('User')

class User(Document, UserMixin):
    meta = {'collection': 'users'}
    email = StringField(max_length=150, unique=True)
    role = StringField(max_length=150)
    password = StringField(max_length=500)
    first_name = StringField(max_length=150)
    failed_login_attempts = IntField(default=0)
    last_failed_login = DateTimeField(default=None)

class Rule(Document):
    meta = {'collection': 'rules'}
    data = StringField(max_length=1000)
    data_type = StringField(max_length=20, choices=[RuleType.KEYWORD, RuleType.CONTEXTUAL, RuleType.PHRASE])
    insertion_time = DateTimeField(default=datetime.datetime.now)
    user_id = ReferenceField('User')

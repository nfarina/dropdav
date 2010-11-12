from google.appengine.ext import db
import hashlib

class DropboxUser(db.Model):
    email = db.StringProperty()
    password = db.StringProperty() # stored as a one-way hash
    access_token = db.StringProperty()

    @classmethod
    def find_by_dropbox_userid(cls, dropbox_userid):
        return cls.all().filter('dropbox_userid =', dropbox_userid).get()
    
    @classmethod
    def find_by_email(cls, email):
        return cls.all().filter('email =', email).get()

    def set_password(self, password):
        self.password = hashlib.md5(password).hexdigest()
    
    def is_password_valid(self, password):
        hash = hashlib.md5(password).hexdigest()
        return hash == self.password

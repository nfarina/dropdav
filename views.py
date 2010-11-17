from datetime import datetime
from dropbox import auth, client
from email.utils import parsedate_tz, mktime_tz
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from models import DropboxUser
from oauth.oauth import OAuthToken
from simpledav.models import Resource
from simpledav.views import DAVHandler
from urllib import pathname2url
from urlparse import urlparse
from xml.etree import ElementTree as ET
import mimetypes
import os

# load the configuration file and make an authenticator
dropbox_ini_path = os.path.join(os.path.dirname(__file__), 'dropbox.ini')
dropbox_config = auth.Authenticator.load_config(dropbox_ini_path)
dropbox_auth = auth.Authenticator(dropbox_config)

# Either dropbox or sandbox
ROOT = "dropbox"

def site_root():
    scheme = "http" if "Development" in os.environ['SERVER_SOFTWARE'] else "https"
    return scheme + "://" + os.environ['HTTP_HOST']

def dropbox_client(access_token):
    return client.DropboxClient(dropbox_config['server'], dropbox_config['content_server'], 
                                80, dropbox_auth, access_token)

class AuthHandler(webapp.RequestHandler):
    def get(self):
        if self.request.GET.has_key('oauth_token'):
            self.dropbox_auth_callback()
        else:
            self.index()

    def post(self):
        if self.request.POST.get('action') == 'setup':
            self.setup()
        elif self.request.POST.get('action') == 'setpass':
            self.set_dropdav_password()

    def index(self):
        path = os.path.join(os.path.dirname(__file__), 'index.html')
        self.response.out.write(template.render(path, {}))
    
    def setup(self):
        # get a fresh request token
        token = dropbox_auth.obtain_request_token()
        self.response.headers['Set-Cookie'] = 'token=%s' % token # we'll need it later
        
        # make the user log in at dropbox.com and authorize this token
        self.redirect(dropbox_auth.build_authorize_url(token,callback=site_root()))
    
    def dropbox_auth_callback(self):
        # now use the authorized token to grab an access token
        token = OAuthToken.from_string(self.request.cookies['token'])
        access_token = dropbox_auth.obtain_access_token(token, "")
        self.response.headers['Set-Cookie'] = 'token=' # erase the auth token
        
        # lookup your account info
        client = dropbox_client(access_token)
        account_info = client.account_info().data
        
        template_params = {
            'access_token':access_token.to_string(),
            'email':account_info['email'],
        }
        
        # prompt you to fill in the account credentials for our system
        path = os.path.join(os.path.dirname(__file__), 'password.html')
        self.response.out.write(template.render(path, template_params))
    
    def set_dropdav_password(self):
        access_token = OAuthToken.from_string(self.request.POST.get('access_token'))
        password = self.request.POST.get('password')
        
        # lookup your account info again to confirm
        client = dropbox_client(access_token)
        account_info = client.account_info().data
        email = account_info['email']
        
        user = DropboxUser.find_by_email(email)
        
        if not user:
            user = DropboxUser(email=email)
                    
        # create or update your user entry in our system
        user.access_token = access_token.to_string()
        user.set_password(password)
        user.put()

        # prompt you to fill in the account credentials for our system
        path = os.path.join(os.path.dirname(__file__), 'success.html')
        self.response.out.write(template.render(path, {'email':email,'server':site_root()}))

class DropboxDAVHandler(DAVHandler):
    def export_meta_entry(self,meta_entry,href=None):
        # make a fake Resource to ease our exporting
        modified = datetime.fromtimestamp(mktime_tz(parsedate_tz(meta_entry['modified']))) if meta_entry.has_key('modified') else datetime.utcnow()
        
        return Resource(
            path = meta_entry['path'].strip('/'),
            is_collection = meta_entry['is_dir'],
            content_length = meta_entry['bytes'],
            created = modified,
            modified = modified,
            
            
        ).export_response(href=href)
    
    def propfind(self):
        path = '/' + self.request_path
        depth = self.request.headers.get('depth','0')
        
        if depth != '0' and depth != '1':
            return self.response.set_status(403,'Forbidden')
        
        metadata = self.client.metadata(ROOT,path).data
        
        if not metadata:
            return self.response.set_status(404,"Not Found")
        
        root = ET.Element('D:multistatus',{'xmlns:D':'DAV:'})
        root.append(self.export_meta_entry(metadata,href=self.request.path)) # first response's href contains exactly what you asked for (relative path)
        
        if metadata.has_key('contents') and depth == '1':
            for entry in metadata['contents']:
                abs_path = site_root() + pathname2url(self._prefix + entry['path'].strip('/').encode('utf-8'))
                root.append(self.export_meta_entry(entry,href=abs_path))

        self.response.headers['Content-Type'] = 'text/xml; charset="utf-8"'
        self.response.set_status(207,'Multi-Status')
        ET.ElementTree(root).write(self.response.out, encoding='utf-8')
    
    def get(self):
        path = '/' + self.request_path
        
        file = self.client.get_file(ROOT,path)
        
        if not file:
            return self.response.set_status(404,"Not Found")
        
        mimetype = mimetypes.guess_type(path,strict=False)[0]
        
        # deliver the file data
        self.response.headers['Content-Type'] = mimetype if mimetype else 'application/octet-stream'
        self.response.out.write(file.read())

    def put(self):
        path = '/' + self.request_path
        self.client.put_file(ROOT, os.path.dirname(path), self.request.body_file, file_name=os.path.basename(path))
        self.response.set_status(201,'Created')

    def mkcol(self):
        path = '/' + self.request_path
        self.client.file_create_folder(ROOT,path)
        self.response.set_status(201,'Created')
    
    def delete(self):
        path = '/' + self.request_path
        self.client.file_delete(ROOT,path)
    
    def move(self):
        path = '/' + self.request_path
        destination = self.request.headers['Destination'] # exception if not present
        
        destination_path = '/' + self.url_to_path(urlparse(destination).path)
        
        if path == destination_path:
            return self.response.set_status(403,"Forbidden")
        
        self.client.file_move(ROOT,path,destination_path)
        self.response.set_status(201)

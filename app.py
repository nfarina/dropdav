from google.appengine.ext.webapp.util import run_wsgi_app
from models import DropboxUser
from oauth.oauth import OAuthToken
from simpledav.wsgi import WSGIApplication
from views import AuthHandler, DropboxDAVHandler, dropbox_client

auth_handler = AuthHandler()

class DropboxWebDAVApplication(WSGIApplication):
    def handle_request(self, environ, request, response):
        method = environ['REQUEST_METHOD']
        
        if True:# or (method == 'GET' or method == 'POST') and request.path == '/':
            return self.handle_main(environ, request, response)
        
        # Check authentication
        (email, password) = self.get_credentials(request)
        
        if email:
            user = DropboxUser.find_by_email(email)
            
            if user and user.is_password_valid(password):
                self._handler.client = dropbox_client(OAuthToken.from_string(user.access_token))
                return super(DropboxWebDAVApplication,self).handle_request(environ,request,response)
            else:
                return self.request_authentication(response)
        else:
            return self.request_authentication(response)
    
    def handle_main(self, environ, request, response):
        method = environ['REQUEST_METHOD']
        auth_handler.initialize(request, response)
        handler_method = getattr(auth_handler,method.lower())
        handler_method()

application = DropboxWebDAVApplication(debug=True,handler_cls=DropboxDAVHandler)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()

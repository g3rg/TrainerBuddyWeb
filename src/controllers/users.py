'''
Created on 18/05/2011

@author: g3rg
'''

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

import os
import logging
from google.appengine.ext.webapp import template

import hashlib
from base64 import b64encode

from model import datastore

class CreateUserPage(webapp.RequestHandler):
    def get(self):
        self.showCreatePage('', '', None)

    def showCreatePage(self, username, email, reason):
        template_values = {
            'username' : username,
            'email' : email,
            'failReason' : reason
        }
        path = os.path.join(os.path.dirname(__file__),'..','web','createuser.html')
        self.response.out.write(template.render(path, template_values))

    def post(self):
        logging.info('Firing create user post handler')
        username = self.request.get('username')
        email = self.request.get('email')
        pass1 = self.request.get('password')
        pass2 = self.request.get('password2')
        
        if username in (None, ''):
            self.showCreatePage('', '', 'Username can not be empty!')
        elif email in (None, ''):
            self.showCreatePage('', '', 'Email can not be empty!')
        elif datastore.User.exists(username):
            logging.info('Username already exists')
            self.showCreatePage(username, email, 'Username already exists')
        elif pass1 in (None, '') or pass1 != pass2 or len(pass1) < 6 :
            logging.info('Passwords failed requirements')
            self.showCreatePage(username, email, 'Passwords are empty, do not match, or are less than 6 characters')
        else:
            logging.info('Request validated')
            user = datastore.User(username=username, email=email)
            user.passwordHash = getPassHash(username, pass1)
            user.save()
            self.redirect('/user/', False)

class LoginUserPage(webapp.RequestHandler):
    def showLoginPage(self, username, msg):
        template_values = {
            'username' : username,
            'failReason' : msg
        }
        path = os.path.join(os.path.dirname(__file__),'..','web','login.html')
        self.response.out.write(template.render(path, template_values))
    
    def get(self):
        self.showLoginPage('', None)
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        if username in (None, ''):
            self.showLoginPage('', 'Please enter your username')
        elif password in (None, ''):
            self.showLoginPage('', 'Please enter your password')
        else :
            passHash = getPassHash(username, password)            
            userCred = datastore.User.getCredentials(username)
            
            if userCred == passHash :
                cookiestr = 'authToken=' + passHash + '; Max-Age=' + str(60)
                self.response.headers.add_header('Set-Cookie', cookiestr)
                cookiestr = 'username=' + username + '; Max-Age=' + str(60)
                self.response.headers.add_header('Set-Cookie', cookiestr)
                self.redirect('/user/', False)
            else:
                self.showLoginPage(username, 'Username and password combination is invalid!')
            
class DefaultUserPage(webapp.RequestHandler):
    def get(self):
        cookies = self.request.cookies
        logging.info(cookies)
        username = None
        token = None
        if 'username' in cookies:
            username = cookies['username']
        if 'token' in cookies:
            token = cookies['authToken']
        if username and token and authToken(username, token):
            self.response.out.write('DEFAULT PAGE REACHED AND LOGGED IN!')
        else:
            self.response.out.write('DEFAULT PAGE REACHED AND NOT LOGGED IN!')

def getPassHash(username, password):
    hash = hashlib.md5()
    hash.update(password)
    tmp = hash.digest()
    hash.update(tmp)
    hash.update(username)
    tmp = hash.digest()
    return b64encode(tmp)
    
def authToken(username, token):
    return token == datastore.User.getCredentials(username)
    
    
def main():
    application = webapp.WSGIApplication(
       [('/user/create', CreateUserPage),
        ('/user/login', LoginUserPage),
        ('/user/*', DefaultUserPage)
        ], debug=True)                          
    #  [('/add_user', UserInsertPage),
    #   ('/users', UsersListPage),
    #   ('/add_credentials', UserCredentialsInsertPage),
    #   ('/add_friend', UserFriendsInsertPage),
    #   ('/user_friends', UserFriendsListPage),
    #   ('/delete_friend', DeleteFriendPage),
    #   ('/edit_user', UserEditPage)
    #  ],
    #  debug=True)
    run_wsgi_app(application)


if __name__ == "__main__":
    main()
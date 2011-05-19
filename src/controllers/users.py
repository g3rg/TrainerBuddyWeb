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

# Set session expiry to 30 minutes for now
SESSION_EXPIRY = 60 * 30

class CreateUserPage(webapp.RequestHandler):
    def get(self):
        self.showCreatePage('', '', None)

    def showCreatePage(self, username, email, reason):
        if checkAuthCookies(self.request.cookies):
            self.redirect('/user/', False)
        else:
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
        if checkAuthCookies(self.request.cookies):
            self.redirect('/user/', False)
        else:        
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
                logging.info ("Setting cookies")
                setAuthCookies(username, password, self.response)
                self.redirect('/user/', False)
            else:
                self.showLoginPage(username, 'Username and password combination is invalid!')
            
class LogoutUserPage(webapp.RequestHandler):
    def logout(self):
        if checkAuthCookies(self.request.cookies):
            clearAuthCookies(self.response)
        
        self.redirect('/user/', False)
        
        
    def get(self):
        self.logout()
        
    def put(self):
        self.logout()            
            
class DefaultUserPage(webapp.RequestHandler):
    def get(self):
        cookies = self.request.cookies
        username = checkAuthCookies(cookies)

        if username != None:
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
    
def checkAuthCookies(cookies):
    logging.info(cookies)
    username = None
    token = None
    
    if 'username' in cookies:
        logging.info('Found username')
        username = cookies['username']
    if 'authToken' in cookies:
        logging.info('Found token')
        token = cookies['authToken']
    auth = False
    if username and token:
        logging.info(username)
        logging.info(token)
        if authToken(username, token):
            logging.info('Authorised')
            auth = True

    if auth :
        return username
    else:
        return None

    
def authToken(username, token):
    return token == datastore.User.getCredentials(username)
    
def setAuthCookies(username, password, response):
    token = getPassHash(username, password)
    cookiestr = 'authToken=' + token + '; Max-Age=' + str(SESSION_EXPIRY)
    response.headers.add_header('Set-Cookie', cookiestr)
    cookiestr = 'username=' + username + '; Max-Age=' + str(SESSION_EXPIRY)
    response.headers.add_header('Set-Cookie', cookiestr)
    
def clearAuthCookies(response):
    response.headers.add_header('Set-Cookie', 'authToken=')
    response.headers.add_header('Set-Cookie', 'username=')    
    
def main():
    application = webapp.WSGIApplication(
       [('/user/create', CreateUserPage),
        ('/user/login', LoginUserPage),
        ('/user/logout', LogoutUserPage),
        ('/user/*', DefaultUserPage)
        ], debug=True)                          
    run_wsgi_app(application)


if __name__ == "__main__":
    main()
'''
Created on 18/05/2011

@author: g3rg
'''

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

import os
import logging
import datetime

from google.appengine.ext.webapp import template

import hashlib
from base64 import b64encode

from model import datastore

# Set session expiry to 30 minutes for now
SESSION_EXPIRY = 60 * 30

class AbstractPage(webapp.RequestHandler):
    def servePage(self, template_values, page):
        path = os.path.join(os.path.dirname(__file__), '..', 'web', page + '.html')
        self.response.out.write(template.render(path,template_values))

class CreateUserPage(AbstractPage):
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
            self.servePage(template_values, 'createuser')

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
    def showLoginPage(self, msg = None, nextPage = None):
        if checkAuthCookies(self.request.cookies):
            if nextPage != None:
                self.redirect('/user/' + nextPage)
            else:
                self.redirect('/user/', False)
        else:
            username = getUsername(self.response.cookies)
            template_values = {
                'username' : username,
                'failReason' : msg,
                'nextPage' : nextPage
            }
            path = os.path.join(os.path.dirname(__file__),'..','web','login.html')
            self.response.out.write(template.render(path, template_values))
    
    def get(self):
        self.showLoginPage(None)
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        nextPage = self.request.get('nextPage')
        
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
                if nextPage not in (None, ''):
                    self.redirect(nextPage, False)
                else :
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

class LodgeUserLocation(webapp.RequestHandler):
    def showLodgeLocationPage(self, lg='', lt='', tm='', srvTm=None, msg=None):
        if not checkAuthCookies(self.request.cookies):
            self.redirect('/user/login', False)
        else:
            username = self.request.cookies['username']
            token = self.request.cookies['authToken']
            
            template_values = {
                'username' : username,
                'lg' : lg,
                'lt' : lt,
                'tm' : tm,
                'msg' : msg
            }
            
            path = os.path.join(os.path.dirname(__file__),'..','web','lodgeloc.html')
            # TODO Set authorisation cookies to keep session alive
            self.response.out.write(template.render(path, template_values))    
            
    def get(self):
        self.showLodgeLocationPage()

    def post(self):
        username = getUsername(self.request.cookies)
        lg = float(self.request.get('lg'))
        lt = float(self.request.get('lt'))
        tm = datetime.datetime.today()
        srvTm = datetime.datetime.today()
        # convert 'None's to empty string!
                
        if lg in (None,'') or lt in (None, '') or tm in (None, ''):
            self.showLodgeLocationPage(lg,lt,tm,None,msg='Please enter all information')
        else:
            loc = datastore.Location(username=username,lg=lg,lt=lt,tm=tm,srvTm=srvTm)
            loc.save()
            self.showLodgeLocationPage(lg=lg, lt=lt, tm=tm, srvTm=srvTm, msg='Lodged Successfully')

class ShowMyLocationsPage(webapp.RequestHandler):
    
    def get(self):
        if checkAuthCookies(self.request.cookies):
            username = getUsername(self.request.cookies)
            myLocs = datastore.Location.getListForUser(username)
            template_values = {
                'username' : username,
                'locs' : myLocs                
            }
            path = os.path.join(os.path.dirname(__file__),'..','web','mylocs.html')
            # TODO Set authorisation cookies to keep session alive
            self.response.out.write(template.render(path, template_values))  
        else:
            #TODO Set nextPage?
            self.redirect('/user/login', )
        
class DataDumpPage(webapp.RequestHandler):
    def get(self):
        # dump 'session' info
        username = getUsername(self.request.cookies)
        # dump users
        users = datastore.User.all()
        userList = []
        for user in users:
            userList.append(user.username)

        template_values = {
            'username' : username,
            'users' : userList,
            'locations' : datastore.Location.all()
        }

        path = os.path.join(os.path.dirname(__file__),'..','web','dump.html')
        # TODO Set authorisation cookies to keep session alive
        self.response.out.write(template.render(path, template_values))           
        

def getPassHash(username, password):
    hash = hashlib.md5()
    hash.update(password)
    tmp = hash.digest()
    hash.update(tmp)
    hash.update(username)
    tmp = hash.digest()
    return b64encode(tmp)
    
def getUsername(cookies):
    username = None
    if 'username' in cookies:
        username = cookies['username']
        
    return username    
    
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
        ('/user/ll', LodgeUserLocation),
        ('/user/dump', DataDumpPage),
        ('/user/myloc', ShowMyLocationsPage),
        ('/user/*', DefaultUserPage)
        ], debug=True)
    run_wsgi_app(application)


if __name__ == "__main__":
    main()
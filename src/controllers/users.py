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
    username = ''
    authToken = None
    
    def servePage(self, template_values, page):
        fullTemplateValues = self.createTemplateVars(template_values)
        path = os.path.join(os.path.dirname(__file__), '..', 'web', page + '.html')
        self.response.out.write(template.render(path,fullTemplateValues))
    
    def setAuthVariables(self):
        cookies = self.request.cookies
        if 'username' in cookies and cookies['username'] not in (None, '', u''):
            self.username = cookies['username']
        else:
            self.username = ''
        
        if 'authToken' in cookies:
            if cookies['authToken'] not in (None, ''):
                self.authToken = cookies['authToken']
            else:
                self.authToken = None

        if self.isUserAuthorised():
            self.setAuthCookies()
            
    def setAuthCookies(self):
        cookiestr = 'authToken=' + self.authToken + '; Max-Age=' + str(SESSION_EXPIRY)
        self.response.headers.add_header('Set-Cookie', cookiestr)
        cookiestr = 'username=' + self.username + '; Max-Age=' + str(SESSION_EXPIRY)
        self.response.headers.add_header('Set-Cookie', cookiestr)

    def isUserAuthorised(self):
        return self.isTokenValid()

    def isTokenValid(self):
        # TODO Implement this correctly!
        return self.username not in (None, '') and self.authToken not in (None, '')
        
    def getPassHash(self, username, password):
        hash = hashlib.md5()
        hash.update(password)
        tmp = hash.digest()
        hash.update(tmp)
        hash.update(username)
        tmp = hash.digest()
        return b64encode(tmp)        
        
    def generateToken(self, username, password):
        # TODO Implement this correctly, don't just use the pass hash! 
        return self.getPassHash(username, password)
                
    def clearAuthDetails(self):
        self.response.headers.add_header('Set-Cookie', 'authToken=')
        self.response.headers.add_header('Set-Cookie', 'username=')
        self.username = ''
        self.authToken = ''
        
    def createTemplateVars(self, vars = {}):
        template_vars = { 'username' : self.username, 'authToken' : self.authToken,
                         'authorised' : self.isUserAuthorised() }
        for var in vars:
            template_vars[var] = vars[var]

        return template_vars

class CreateUserPage(AbstractPage):
    def get(self):
        self.setAuthVariables()
        if not self.isUserAuthorised():
            self.showCreatePage('', '', None)
        else:
            self.servePage({'msg':'Please log out if you want to create a new user'}, 'home')

    def showCreatePage(self, username, email, reason):
        template_values = {
            'username' : username,
            'email' : email,
            'failReason' : reason
        }
        self.servePage(template_values, 'createuser')

    def post(self):
        self.setAuthVariables()
        if not self.isUserAuthorised():
            username = self.request.get('username')
            email = self.request.get('email')
            pass1 = self.request.get('password')
            pass2 = self.request.get('password2')
            
            if username in (None, ''):
                self.showCreatePage('', '', 'Username can not be empty!')
            elif email in (None, ''):
                self.showCreatePage('', '', 'Email can not be empty!')
            elif datastore.User.exists(username):
                self.showCreatePage(username, email, 'Username already exists')
            elif pass1 in (None, '') or pass1 != pass2 or len(pass1) < 6 :
                self.showCreatePage(username, email, 'Passwords are empty, do not match, or are less than 6 characters')
            else:
                user = datastore.User(username=username, email=email)
                user.passwordHash = self.getPassHash(username, pass1)
                user.save()
                self.redirect('/user/', False)

class LoginUserPage(AbstractPage):
    def showLoginPage(self, msg = None):
        self.setAuthVariables()
        if self.isUserAuthorised():
            self.redirect('/user/', False)
        else:
            template_values = {
                'failReason' : msg,
            }
            self.servePage(template_values, 'login')
    
    def get(self):
        self.showLoginPage(None)
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        if username in (None, ''):
            self.showLoginPage('', 'Please enter your username')
        elif password in (None, ''):
            self.showLoginPage('', 'Please enter your password')
        else :
            passHash = self.getPassHash(username, password)            
            userCred = datastore.User.getCredentials(username)
            
            if userCred == passHash :
                self.authToken = self.generateToken(self.username, password)
                self.username = username
                self.setAuthCookies()
                self.redirect('/user/', False)
            else:
                self.showLoginPage(username, 'Username and password combination is invalid!')
            
class LogoutUserPage(AbstractPage):
    def logout(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            self.clearAuthDetails()
        
        self.redirect('/user/', False)
        
    def get(self):
        self.logout()
        
    def put(self):
        self.logout()            
            
class DefaultUserPage(AbstractPage):
    def get(self):
        self.setAuthVariables()
        self.servePage({}, 'home')

class LodgeUserLocation(AbstractPage):
    def showLodgeLocationPage(self, lg='', lt='', tm='', srvTm=None, msg=None):
        self.setAuthVariables()
        if not self.isUserAuthorised():
            self.redirect('/user/login', False)
        else:
            template_values = {
                'lg' : lg,
                'lt' : lt,
                'tm' : tm,
                'msg' : msg
            }
            self.servePage(template_values, 'lodgeloc')
            
    def get(self):
        self.showLodgeLocationPage()

    def post(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            lg = float(self.request.get('lg'))
            lt = float(self.request.get('lt'))
            tm = datetime.datetime.today()
            srvTm = datetime.datetime.today()
            # convert 'None's to empty string!
                    
            if lg in (None,'') or lt in (None, '') or tm in (None, ''):
                self.showLodgeLocationPage(lg,lt,tm,None,msg='Please enter all information')
            else:
                loc = datastore.Location(username=self.username,lg=lg,lt=lt,tm=tm,srvTm=srvTm)
                loc.save()
                self.showLodgeLocationPage(lg=lg, lt=lt, tm=tm, srvTm=srvTm, msg='Lodged Successfully')
        else :
            self.redirect('/user/login', False)

class ShowMyLocationsPage(AbstractPage):
    
    def get(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            myLocs = datastore.Location.getListForUser(self.username)
            template_values = {
                'locs' : myLocs                
            }
            self.servePage(template_values, 'mylocs')
        else:
            self.redirect('/user/login', )
        
class DataDumpPage(AbstractPage):
    def get(self):
        self.setAuthVariables()
        # dump 'session' info
        username = self.username
        # dump users
        users = datastore.User.all()
        userList = []
        for user in users:
            userList.append(user.username)

        template_values = {
            'users' : userList,
            'locations' : datastore.Location.all()
        }
        self.servePage(template_values, 'dump')
    
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
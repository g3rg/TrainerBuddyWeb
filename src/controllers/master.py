'''
Created on 18/05/2011

@author: g3rg
'''

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from django.utils import simplejson

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
    
    def login(self, username, password):
        passHash = self.getPassHash(username, password)            
        userCred = datastore.User.getCredentials(username)
        result = False
        
        if userCred == passHash :
            self.username = username
            self.authToken = self.generateToken()
            self.setAuthCookies()
            result = True
            
        return result
    
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
        # validate user exists
        username = self.username
        if username not in (None, ''):
            cred = datastore.User.getCredentials(username)
            if cred not in (None, ''):
                return self.isTokenValid()
            
        return False

    def isTokenValid(self, token=None):
        # TODO Implement this correctly!
        valid = False
        
        if token == None:
            token = self.authToken
        
        if self.username not in (None, '') and self.authToken not in (None, ''):
            valid = self.generateToken() == token
            
        return valid

        
        
    def getPassHash(self, username, password):
        hash = hashlib.md5()
        hash.update(password)
        tmp = hash.digest()
        hash.update(tmp)
        hash.update(username)
        tmp = hash.digest()
        return b64encode(tmp)        
        
    def generateToken(self):
        # TODO Implement this correctly, don't just use the pass hash!
        userCred = datastore.User.getCredentials(self.username)
        return self.getPassHash(self.username, userCred)
                
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
            if self.login(username, password):
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
                user = datastore.User.getByUsername(self.username)
                loc = datastore.Location(username=user,lg=lg,lt=lt,tm=tm,srvTm=srvTm)
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
            self.redirect('/user/login', False)

class EditGroupPage(AbstractPage):
    def get(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            groupName = self.request.get('gp')
            group = datastore.Group.getGroup(groupName)
            
            members = group.getMembers()
            memberKeys = [member.key() for member in members]
            invitees = group.getInvitees()
            inviteeKeys = [invitee.key() for invitee in invitees]
            logging.info("test")
            friends = [friend.friend for friend in datastore.Friend.getFriends(self.username)
                       if friend.friend.key() not in memberKeys and friend.friend.key() not in inviteeKeys]

            template_values = {
                'group' : group,
                'members' : members,
                'invitees' : invitees,
                'friends': friends
            }
            self.servePage(template_values, 'group')
        else:
            self.redirect('/user/login', False)

    def invite(self, group, friendKey):
        selectedUser = datastore.User.getByKey(friendKey)
        
        if selectedUser and selectedUser.key() not in group.members and selectedUser.key() not in group.invitees:
            
            group.invitees.append(selectedUser.key())
            group.save()

    def uninvite(self, group, friendKey):
        logging.info('Uninviting ' + friendKey + ' from ' + group.groupName)
        selectedUser = datastore.User.getByKey(friendKey)
        if selectedUser and selectedUser.key() not in group.members and selectedUser.key() in group.invitees:
            group.invitees.remove(selectedUser.key())
            group.save()

    def remove(self, group, friendKey):
        logging.info('Removing ' + friendKey + ' from ' + group.groupName)
        selectedUser = datastore.User.getByKey(friendKey)
        if selectedUser and selectedUser.key() in group.members:
            group.members.remove(selectedUser.key())
            group.save()

    def post(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            groupName = self.request.get('gp')
            selectedFriend = self.request.get('selectedFriend')
            subaction = self.request.get('subaction')
            
            group = datastore.Group.getGroup(groupName)
            
            if subaction not in (None, ''):
                {'invite':self.invite, 'uninvite':self.uninvite, 'remove':self.remove}[subaction](group, selectedFriend);

            members = group.getMembers()
            memberKeys = [member.key() for member in members]
            invitees = group.getInvitees()
            inviteeKeys = [invitee.key() for invitee in invitees]
            logging.info("test")
            friends = [friend.friend for friend in datastore.Friend.getFriends(self.username)
                       if friend.friend.key() not in memberKeys and friend.friend.key() not in inviteeKeys]

            template_values = {
                'group' : group,
                'members' : members,
                'invitees' : invitees,
                'friends': friends
            }            
            
            self.servePage(template_values, 'group')
        else:
            self.redirect('/user/login', False)

class EditGroupsPage(AbstractPage):
    subaction = None
    
    def get(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            owned = datastore.Group.getGroupsOwned(self.username)
            groups = datastore.Group.getGroups(self.username)
            inviteGroups = datastore.Group.getInviteGroups(self.username)
            template_values = {
                'ownedGroups' : owned,
                'groups' : groups,
                'inviteGroups' : inviteGroups
            }
            self.servePage(template_values, 'groups')
        else:
            self.redirect('/user/login', False)
            
            
    def confirm(self, selectedGroup):
        # find the group
        group = datastore.Group.getGroup(selectedGroup)
        username = self.username
        user = datastore.User.getByUsername(username)
         
        if user.key() in group.invitees:
            if not user.key() in group.members:
                group.members.append(user.key())
                
            group.invitees.remove(user.key())
            group.save()
        
        
    def removeMe(self, selectedGroup):
        logging.info("Removing " + self.username + " from " + selectedGroup)
        group = datastore.Group.getGroup(selectedGroup)
        username = self.username
        user = datastore.User.getByUsername(username)
        
        if user.key() in group.members:
            group.members.remove(user.key())
            if not user.key() in group.invitees:
                group.invitees.append(user.key())
                
            group.save()

    def ignore(self, selectedGroup):
        logging.info(self.username + " is ignoring invite to " + selectedGroup)
        group = datastore.Group.getGroup(selectedGroup)
        username = self.username
        user = datastore.User.getByUsername(username)
        
        if user.key() not in group.members and user.key() in group.invitees:
            group.invitees.remove(user.key())
            
        group.save()
            
                
    def post(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            logging.info('Handling authorised group post request')
            # find user
            newGroup = self.request.get('groupname')
            selectedGroup = self.request.get('selectedGroup')
            subaction = self.request.get('subaction')
            
            msg = ''
            if subaction not in (None, ''):
                {'confirm':self.confirm, 'removeMe':self.removeMe, 'ignore':self.ignore}[subaction](selectedGroup)
                logging.info('Handle subaction ' + subaction)
            elif newGroup not in (None, ''):
                logging.info('Creating New Group')
                if datastore.Group.exists(newGroup):
                    logging.info('Group exists')
                    msg = 'Group ' + newGroup + ' already exists'
                else:
                    group = datastore.Group(groupName=newGroup, owner=datastore.User.getByUsername(self.username))
                    user = datastore.User.getByUsername(self.username)
                    group.members.append(user.key())
                    group.save()

            owned = datastore.Group.getGroupsOwned(self.username)
            groups = datastore.Group.getGroups(self.username)
            inviteGroups = datastore.Group.getInviteGroups(self.username)
            template_values = {
                'ownedGroups' : owned,
                'groups' : groups,
                'inviteGroups' : inviteGroups
            }
            self.servePage(template_values, 'groups')        
        else:
            self.servePage('/user/login', False)

class EditFriendsPage(AbstractPage):
    subaction = None
    selectedFriend = None
    
    def get(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            friends = datastore.Friend.getFriends(self.username)
            template_values = {
                'friends':friends
            }
            self.servePage(template_values, 'friends')
        else:
            self.redirect('/user/login', False)        
        
    def confirm(self, selectedFriend):
        logging.info('Confirming ' + selectedFriend)
        datastore.Friend.confirmFriend(self.username, selectedFriend)

    def remove(self, selectedFriend):
        logging.info('Removing ' + selectedFriend)
        datastore.Friend.removeFriend(self.username, selectedFriend)
        
    def share(self, selectedFriend):
        logging.info('Sharing location with ' + selectedFriend)
        datastore.Friend.shareLocation(self.username, selectedFriend)
        
    def unshare(self, selectedFriend):
        logging.info('Unsharing location with ' + selectedFriend)
        datastore.Friend.unShareLocation(self.username, selectedFriend)
        
    def post(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            # find user
            newFriend = self.request.get('friendname')
            selectedFriend = self.request.get('selectedFriend')
            subaction = self.request.get('subaction')
            
            msg = ''
            if subaction not in (None, ''):
                {'confirm':self.confirm,'remove':self.remove,'share':self.share,'unshare':self.unshare}[subaction](selectedFriend);
            elif newFriend not in (None, '', self.username):
                logging.info('Creating New Friend')
                if datastore.User.exists(newFriend):
                    logging.info('Friend exists')
                    # check to see if already friends
                    if not datastore.Friend.alreadyFriends(self.username, newFriend):
                        user = datastore.User.getByUsername(self.username)
                        friendUser = datastore.User.getByUsername(newFriend)
                        friend = datastore.Friend(user=user, friend=friendUser, confirmed=True)
                        friend.save()
                        friend = datastore.Friend(user=friendUser, friend=user, confirmed=False)
                        friend.save()
                    else:
                        logging.info('Already friends')
                else:
                    logging.info('Friend not found')
                    msg = 'Friend not found'

            friends = datastore.Friend.getFriends(self.username)
            template_values = {
                'friends': friends,
                'failReason' : msg
            }
            self.servePage(template_values, 'friends')
        else:
            self.redirect('/user/login', False)       
    
class EditRidePage(AbstractPage):
    def get(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            rideKey = self.request.get('rd')
            ride = datastore.Ride.get([rideKey])[0]

            if ride.date:
                ridedate = ride.date.date()
                ridetime = ride.date.time() 
            else:
                ridedate = ''
                ridetime = ''
            
            friends = [friend.friend for friend in datastore.Friend.getFriends(self.username)
                       if friend.friend not in ride.getRiders()]
            
            participants = ride.riders
            
            template_values = {
                'ride' : ride,
                'rideKey' : rideKey,
                'ridedate' : ridedate,
                'ridetime' : ridetime,
                'friends' : friends,
                'participants' : participants
            }
            self.servePage(template_values, 'ride')
        else:
            self.redirect('/user/login', False)


    def invite(self, ride, friendKey):
        selectedUser = datastore.User.getByKey(friendKey)
        
        if selectedUser and selectedUser not in ride.getRiders():
            logging.info('Inviting ' + selectedUser.username + ' to ' + ride.title)
            rider = datastore.RideParticipant(ride=ride,user=selectedUser,status=datastore.STATUS_INVITED)
            rider.save()
            
                        
        #if selectedUser and selectedUser.key() not in ride.undecided:
        #    ride.undecided.append(selectedUser.key())
        #    ride.save()
    
    def uninvite(self, ride, selectedFriend):
        logging.info('Uninviting ' + selectedFriend.name + ' ' + ride.title)
    
    def post(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            rideKey = self.request.get('rd')
            ride = datastore.Ride.get([rideKey])[0]
            subaction = self.request.get('subaction')
            selectedFriend = self.request.get('selectedFriend')
            
            if ride.date:
                ridedate = ride.date.date()
                ridetime = ride.date.time() 
            else:
                ridedate = ''
                ridetime = ''            
            
            if subaction not in (None, ''):
                {'invite':self.invite, 'uninvite':self.uninvite}[subaction](ride, selectedFriend);
            else :
                title = self.request.get('title')
                description = self.request.get('description')
                dt = self.request.get('date')
                tm = self.request.get('time')
                
                ride.title = title
                ride.description = description
                if (dt and tm):
                    ride.date = datetime.datetime.strptime(dt + 'T' + tm, '%Y-%m-%dT%H:%M:%S')
                    ridedate = dt
                    ridetime = tm
                
                ride.save()
                
                        
            friends = [friend.friend for friend in datastore.Friend.getFriends(self.username)
                       if friend.friend.key() not in ride.riders]
            
            participants = ride.getRiders()
            
            template_values = {
                'ride' : ride,
                'rideKey' : rideKey,
                'ridedate' : ridedate,
                'ridetime' : ridetime,
                'friends' : friends,
                'participants' : participants
            }
            
            self.servePage(template_values, 'ride')
        else:
            self.redirect('/user/login', False)
    
    
class EditRidesPage(AbstractPage):
    def get(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            createdRides = datastore.Ride.getCreatedRides(self.username)
            # invitedRides = datastore.Ride.getInvitedRides(self.username)
            
            template_values = {
                'createdRides' : createdRides
             #   'invitedRides' : invitedRides
            }
            self.servePage(template_values, 'rides')
        else:
            self.redirect('/user/login', False)        
    
    def post(self):
        self.setAuthVariables()
        if self.isUserAuthorised():
            # find user
            newRide = self.request.get('ridename')
            subaction = self.request.get('subaction')
            
            msg = ''
            if subaction not in (None, ''):
                {}[subaction]();
            elif newRide not in (None, ''):
                #if datastore.Ride.exists(newRide):
                if datastore.Ride.existsForCreator(newRide, self.username):
                    msg = 'Ride with that name already exists'
                else:
                    ride = datastore.Ride(title=newRide,creator = datastore.User.getByUsername(self.username))
                    ride.save()

            createdRides = datastore.Ride.getCreatedRides(self.username)
            
            template_values = {
                'failReason' : msg,
                'createdRides' : createdRides
            }
            self.servePage(template_values, 'rides')
        else:
            self.redirect('/user/login', False)           
    
class DataDumpPage(AbstractPage):
    def get(self):
        self.setAuthVariables()
        # dump users
        users = datastore.User.all()
        userList = []
        for user in users:
            userList.append(user.username)

        friends = datastore.Friend.all()
        friendList = []
        for friend in friends:
            friendStr = friend.user.username +  ' - ' + friend.friend.username + ' - ' 
            if friend.confirmed:
                friendStr = friendStr + ' CONFIRMED'
            friendList.append(friendStr)

        groups = datastore.Group.all()
        groupList = []
        for group in groups:
            members = group.getMembers()
            memberStr = ''
            
            for member in members:
                memberStr = memberStr + member.username + ','
            inviteeStr = ''
            invitees = group.getInvitees()
            for invitee in invitees:
                inviteeStr = inviteeStr + invitee.username + ','             
                
            groupStr = group.groupName + ' - ' + group.owner.username + ' - ' + memberStr + " - " + inviteeStr
            groupList.append(groupStr)

        rides = datastore.Ride.all()
        rideList = []
        for ride in rides:
            ridestr = ride.title + ' - ' + ride.creator.username + ' - ' + ride.description
            rideList.append(ridestr)

        template_values = {
            'users' : userList,
            'friends' : friendList,
            'groups' : groupList,
            'rides' : rideList
        }
        self.servePage(template_values, 'dump')
    
class LoginJson(AbstractPage):
    def post(self):
        #self.response.headers['Access-Control-Allow-Origin'] = '*'
        #self.response.headers['Access-Control-Allow-Headers'] = '*'
        #self.response.headers['Access-Control-Allow-Methods'] = 'POST'      
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers.add_header("Access-Control-Allow-Headers", "*")  
        logging.info("Attempting JSON login")
        msg = None
        token = None
        username = None
        password = None
        
        req = simplejson.loads(self.request.body)
        
        if "username" in req:
            username = req["username"]
        if "password" in req:
            password = req["password"]
        
        if username in (None, '') or password in (None, ''):
            msg = 'Parameters not complete'
        else:
            if self.login(username, password):
                token = self.authToken
            else:
                msg = 'Login failed'
        
        self.response.headers['Access-Control-Allow-Origin'] = self.request.headers['Origin']
        self.response.out.write(simplejson.dumps({"msg":msg, "token":token}))

    def options(self):
        logging.info("Executing options")
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers.add_header("Access-Control-Allow-Headers", "Content-Type")

class AbstractJSON(AbstractPage):
    req = None
    uesrname = None
    token = None
    authorised = False
    
    def checkRequest(self):
        logging.info('Ajax Request:' + self.request.body)        
        self.req = simplejson.loads(self.request.body)
        
        if "username" in self.req:
            self.username = self.req["username"]
        if "token" in self.req:
            self.authToken = self.req["token"]
            
        if self.username in (None, '') or self.authToken in (None, '') or not self.isTokenValid():
            self.authorised = False
        else:
            self.authorised = True
            
    def options(self):
        logging.info("Executing options")
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        self.response.headers.add_header("Access-Control-Allow-Headers", "Content-Type")
        
class LodgeCurrentUserInfoJSON(AbstractJSON):
    def post(self):
        self.checkRequest()
        data = None
        msg = None

        if self.authorised:
            if "locations" in self.req:
                locationsSaved = []
                locationsFailed = []
                for location in self.req["locations"]:
                    lg = None
                    lt = None
                    tm = None
                    corrId = None
                    srvTm = datetime.datetime.today()
            
                    if "lg" in location:
                        lg = float(location['lg'])
                    if "lt" in location:
                        lt = float(location['lt'])
                    if "tm" in location:
                        tm = datetime.datetime.strptime(location['tm'], '%Y-%m-%dT%H:%M:%S')
                    if "corrId" in location:
                        corrId = int(location["corrId"])

                    if lg in (None,'') or lt in (None, ''):
                        if corrId in (None, ''):
                            locationsFailed.append("%f, %f"%(lg,lt))
                        else:
                            locationsFailed.append(corrId)
                    else:
                        user = datastore.User.getByUsername(self.username)
                        loc = datastore.Location(user=user,lg=lg,lt=lt,tm=tm,srvTm=srvTm,corrId=corrId)
                        loc.save()
                        if corrId in (None, ''):
                            locationsSaved.append("%f, %f"%(lg,lt))
                        else:
                            locationsSaved.append(corrId)
                data = {"saved":locationsSaved, "failed":locationsFailed}
                msg = "Locations processed" 
            else:
                msg = "Missing locations data"
        else:
            msg = 'Not Authorised'

        self.response.headers.add_header('Access-Control-Allow-Origin', '*')            
        self.response.out.write(simplejson.dumps({"msg":msg, "data":data}))
            
    
class RPCTestPage(AbstractPage):
    def get(self):
        self.servePage({}, 'test')    
    
def main():
    application = webapp.WSGIApplication(
       [('/user/create', CreateUserPage),
        ('/user/login', LoginUserPage),
        ('/user/logout', LogoutUserPage),
        ('/user/ll', LodgeUserLocation),
        ('/user/dump', DataDumpPage),
        ('/user/myloc', ShowMyLocationsPage),
        ('/json/rpctst', RPCTestPage),
        ('/user/rpctst', RPCTestPage),
        ('/user/friends', EditFriendsPage),
        ('/user/groups', EditGroupsPage),
        ('/user/group', EditGroupPage),
        ('/user/rides', EditRidesPage),
        ('/user/ride', EditRidePage),
        ('/json/ll', LodgeCurrentUserInfoJSON),
        ('/json/login', LoginJson),
        ('/user/*', DefaultUserPage)
        ], debug=True)
    run_wsgi_app(application)


if __name__ == "__main__":
    main()
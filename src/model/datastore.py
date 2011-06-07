'''
Created on 18/05/2011

@author: g3rg
'''
import logging
import datetime

from google.appengine.ext import db

class User(db.Model):
    username = db.StringProperty(required=True)
    email = db.EmailProperty(required=True)
    passwordHash = db.StringProperty(multiline=True)
    
    @classmethod
    def getCredentials(cls, username):
        if username not in (None, ''):
            query = cls.gql('WHERE username = :1', username)
            user = query.get()
            if user:
                return query.get().passwordHash
            else:
                return None
        return None
    
    @classmethod
    def getUser(cls, username):
        user = None
        if username not in (None, ''):
            query = cls.gql('WHERE username = :1', username)
            user = query.get()
        return user
    
    @classmethod
    def exists(cls, username):
        if username not in (None, ''):
            query = cls.gql('WHERE username = :1', username)
            return query.get() != None
    

class Group(db.Model):
    groupName = db.StringProperty(required=True)
    owner = db.ReferenceProperty(reference_class=User, required=True)
    members = db.ListProperty(db.Key)
    invitees = db.ListProperty(db.Key)
    
    def getMembers(self):
        members = [db.get(key) for key in self.members]
        
        memberList = []
        for member in members:
            memberList.append(member)
            
        return memberList
    
    def getInvitees(self):
        invitees = [db.get(key) for key in self.invitees]
        
        inviteeList = []
        for invitee in invitees:
            inviteeList.append(invitee)
            
        return inviteeList
        
    
    @classmethod
    def getGroup(cls, groupName):
        query = cls.gql('WHERE groupName = :1', groupName)
        group = query.get()
        return group
    
    @classmethod
    def getGroupsOwned(cls, username):
        groups = []
        if username not in (None, ''):
            user = User.getUser(username)
            query = cls.gql('WHERE owner = :1', user)
            for group in query:
                groups.append(group)
            
        return groups
    
    @classmethod
    def getInviteGroups(cls, username):
        groups = []
        if username not in (None, ''):
            user = User.getUser(username)
            query = cls.gql('WHERE invitees = :1', user.key())
            for group in query:
                groups.append(group)
        return groups
    
    @classmethod
    def getGroups(cls, username):
        # CHANGE TO ONLY GET GROUPS THE USER IS IN
        groups = []
        if username not in (None, ''):
            user = User.getUser(username)
            query = cls.gql('WHERE owner != :1 AND members = :2', user, user.key())
            for group in query:
                groups.append(group)
            
        return groups        
    
    @classmethod
    def exists(cls, groupname):
        if groupname not in (None, ''):
            query = cls.gql('WHERE groupName = :1', groupname)
            return query.get() != None

class Friend(db.Model):
    user = db.ReferenceProperty(reference_class=User,required=True, collection_name='user_reference')
    friend = db.ReferenceProperty(reference_class=User,required=True, collection_name='friend_reference')
    
    confirmed = db.BooleanProperty(required=True, default=False)
    sharingLocation = db.BooleanProperty(required=False, default=False)
    
    @classmethod
    def removeFriend(cls, username, friendKey):
        friendsDeleted = 0
        user = User.getUser(username)
        friend = User.get([friendKey])[0]
        query = cls.gql('WHERE user = :1 AND friend = :2', user, friend)
        
        for f in query:
            f.delete()
            friendsDeleted = friendsDeleted + 1
            
        logging.info('Friends deleted ' + `friendsDeleted`)
    
    @classmethod
    def confirmFriend(cls, username, friendKey):
        
        friendsConfirmed = 0
        user = User.getUser(username)
        friend = User.get([friendKey])[0]
        
        query = cls.gql('WHERE user = :1 AND friend = :2 and confirmed = False', user, friend)
        
        for f in query:
            f.confirmed = True
            f.save()
            friendsConfirmed = friendsConfirmed + 1

        logging.info('Friends confirmed ' + `friendsConfirmed`)
    
    @classmethod
    def shareLocation(cls, username, friendKey):
        friendsAltered = 0
        user = User.getUser(username)
        friend = User.get([friendKey])[0]        
        query = cls.gql('WHERE user = :1 AND friend = :2 and confirmed = True', user, friend)
        
        for f in query:
            f.sharingLocation = True
            f.save()
            friendsAltered = friendsAltered + 1
            
        logging.info('Friends altered for sharing ' + `friendsAltered`)    
    
    @classmethod
    def unShareLocation(cls, username, friendKey):
        friendsAltered = 0
        user = User.getUser(username)
        friend = User.get([friendKey])[0]  
        query = cls.gql('WHERE user = :1 AND friend = :2 and confirmed = True', user, friend)
        
        for f in query:
            f.sharingLocation = False
            f.save()
            friendsAltered = friendsAltered + 1
            
            
        logging.info('Friends altered for sharing ' + `friendsAltered`)      
    
    @classmethod
    def getFriends(cls, username):
        friends = []
        if username not in (None, ''):
            user = User.getUser(username)
            query = cls.gql('WHERE user = :1 ORDER by confirmed, friend', user)
            for f in query:
                friends.append(f)
            
        return friends
    
    @classmethod
    def alreadyFriends(cls, username, friendname):
        user = User.getUser(username)
        friend = User.getUser(friendname)
        
        query = cls.gql('WHERE user = :1 AND friend = :2', user, friend)

        return query.count(1) > 0


class RideComment(db.Model):
    date = db.DateTimeProperty(default=datetime.datetime.today())
    user = db.ReferenceProperty(reference_class=User)
    comment = db.StringProperty()

class Ride(db.Model):
    title = db.StringProperty(required=True)
    description = db.StringProperty()
    #http://code.google.com/appengine/docs/python/datastore/typesandpropertyclasses.html#ReferenceProperty
    creator = db.ReferenceProperty(reference_class=User)
    date = db.DateTimeProperty()
    
    # TODO Add this as lists of keys into datastore.User
    #undecided = db.StringListProperty()
    #confirmed = db.StringListProperty()
    #rejected = db.StringListProperty()
    #comments = db.ListProperty(db.Key)
    
    @classmethod
    def getCreatedRides(cls, username):
        user = User.getUser(username)
        query = cls.gql('WHERE creator = :1', user)
        rides = []
        for ride in query:
            rides.append(ride)
        return rides
    
    @classmethod
    def exists(cls, ridename):
        if ridename not in (None, ''):
            query = cls.gql('WHERE title = :1', ridename)
            return query.get() != None    

class Location(db.Model):
    user = db.ReferenceProperty(reference_class=User,required=True)
    lg = db.FloatProperty()
    lt = db.FloatProperty()
    alt = db.FloatProperty()
    tm = db.DateTimeProperty()
    srvTm = db.DateTimeProperty()
    corrId = db.IntegerProperty()
    
    @classmethod
    def getListForUser(cls, username):
        if username not in (None, ''):
            user = User.getUser(username)
            query = cls.gql('WHERE user = :1 ORDER BY tm DESC LIMIT 100', user)
            return query

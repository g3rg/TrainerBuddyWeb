'''
Created on 18/05/2011

@author: g3rg
'''
import logging

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
    
    @classmethod
    def exists(cls, username):
        if username not in (None, ''):
            query = cls.gql('WHERE username = :1', username)
            return query.get() != None

class Friend(db.Model):
    username = db.StringProperty(required=True)
    friend = db.StringProperty(required=True)
    confirmed = db.BooleanProperty(required=True, default=False)
    sharingLocation = db.BooleanProperty(required=False, default=False)
    
    @classmethod
    def removeFriend(cls, username, friendName):
        friendsDeleted = 0
        query = cls.gql('WHERE username = :1 AND friend = :2', username, friendName)
        
        for friend in query:
            friend.delete()
            friendsDeleted = friendsDeleted + 1
            
        logging.info('Friends deleted ' + `friendsDeleted`)
    
    @classmethod
    def confirmFriend(cls, username, friendName):
        friendsConfirmed = 0
        query = cls.gql('WHERE username = :1 AND friend = :2 and confirmed = False', username, friendName)
        
        for friend in query:
            friend.confirmed = True
            friendsConfirmed = friendsConfirmed + 1
            friend.save()
            
            logging.info('Friends confirmed ' + `friendsConfirmed`)
    
    @classmethod
    def shareLocation(cls, username, friendName):
        friendsAltered = 0
        query = cls.gql('WHERE username = :1 AND friend = :2 and confirmed = True', username, friendName)
        
        for friend in query:
            friend.sharingLocation = True
            friendsAltered = friendsAltered + 1
            friend.save()
            
            logging.info('Friends altered for sharing ' + `friendsAltered`)    
    
    @classmethod
    def unShareLocation(cls, username, friendName):
        friendsAltered = 0
        query = cls.gql('WHERE username = :1 AND friend = :2 and confirmed = True', username, friendName)
        
        for friend in query:
            friend.sharingLocation = False
            friendsAltered = friendsAltered + 1
            friend.save()
            
            logging.info('Friends altered for sharing ' + `friendsAltered`)      
    
    @classmethod
    def getFriends(cls, username):
        friends = []
        if username not in (None, ''):
            query = cls.gql('WHERE username = :1 ORDER by confirmed, friend', username)
            for friend in query:
                friends.append(friend)
            
        return friends
    
    @classmethod
    def alreadyFriends(cls, username, friendname):
        query = cls.gql('WHERE username = :1 AND friend = :2', username, friendname)

        return query.count(1) > 0
    
            
class Location(db.Model):
    username = db.StringProperty(required=True)
    lg = db.FloatProperty()
    lt = db.FloatProperty()
    alt = db.FloatProperty()
    tm = db.DateTimeProperty()
    srvTm = db.DateTimeProperty()
    corrId = db.IntegerProperty()
    
    @classmethod
    def getListForUser(cls, username):
        if username not in (None, ''):
            query = cls.gql('WHERE username = :1 ORDER BY tm DESC LIMIT 100', username)
            return query

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
    
    @classmethod
    def getFriends(cls, username):
        friends = []
        if username not in (None, ''):
            query = cls.gql('WHERE username = :1 AND confirmed = TRUE ORDER by confirmed, friend', username)
            for friend in query:
                friends.append(friend.friend)
            
        return friends
    
    @classmethod
    def alreadyFriends(cls, username, friendname):
        query = cls.gql('WHERE username = :1 AND friend = :2', username, friendname)
        return query.fetch(1) > 0
    
            
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

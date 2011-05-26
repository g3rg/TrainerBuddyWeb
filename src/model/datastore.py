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

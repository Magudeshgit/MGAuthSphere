from django.utils import timezone
from datetime import timedelta, datetime
from django.utils.crypto import get_random_string
from .models import MGRealm, MGRealm_Sessions
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.sessions.base_session import BaseSessionManager
import string

VALID_KEY_CHARS = string.ascii_lowercase + string.digits

class SessionHandler:
    def __init__(self):
        self.usermodel = MGRealm
        self.sessmodel = MGRealm_Sessions
    # Utilities
        
    def new_session_key(self):
        """
        Creates A New Session Key, An Utility Function
        """
        return get_random_string(32, VALID_KEY_CHARS)
    
    def set_expiry(self, date=None):
        """
        return the standard expiration period for a session key
        """
        if date==None:
            return timezone.localdate() + timedelta(days=14) 
        else:
            return str(datetime(date) + timedelta(days=14) )

    # Validators and Handlers
    def create_session(self, user_id=None): 
        """
            Suite Function, Creates a Session associated with user and returns the created object
        """
        userobj = self.usermodel.objects.get(id=user_id)
        # Avoid not unique constraint error
        if self.sessmodel.objects.filter(user = userobj).exists():
            self.sessmodel.objects.filter(user = userobj).delete()

        return self.sessmodel.objects.create(
            session_key = self.new_session_key(),
            expire_date = self.set_expiry(),
            user = userobj
        )
    def update_session(self, session_id):
        try:
            session = self.sessmodel.objects.get(session_key = session_id)
            session.expire_date = self.set_expiry()
            session.save()
        except ObjectDoesNotExist:
            return False

    def check_login(self, Session_key):
        """
        Checks for the expiration of the provided Session_key
        """
        session = self.sessmodel.objects.filter(session_key=Session_key)
        msg = "success"

        if not session.exists():
            return "session does not exist", False
        
        if session[0].user.is_active:
            if timezone.localdate() < session[0].expire_date:
                return msg, session[0].user 
            else:
                msg = "session expired"
                user = session[0].user
                session[0].delete()
                return msg, user
        else:
            flag = False
            msg = "user access revoked"
            return msg, session[0].user   
    
    def get_corresponding_user(self, Session_key):
        """
        Returns the user associated with specified Session, False if none
        """
        try:
            session = self.sessmodel.objects.get(session_key=Session_key)
            return session.user
        except ObjectDoesNotExist:
            return False
        

    def logout(self, Session_key):
        """
        Clears the session of the provided
        """
        session = self.sessmodel.objects.filter(session_key=Session_key)
        if session.exists():
            session[0].delete()
            return True
        else:
            return False
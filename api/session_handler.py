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
        return get_random_string(32, VALID_KEY_CHARS)
    
    def set_expiry(self, date=None):
        print('sd',date)
        if date==None:
            return timezone.localdate() + timedelta(days=14) 
        else:
            return str(datetime(date) + timedelta(days=14) )

    # Validators and Handlers
    def create_session(self, user_id=None): #Methods: Authenticate
        userobj = self.usermodel.objects.get(id=user_id)
        # Avoid not unique constraint error
        if self.sessmodel.objects.filter(user = userobj).exists():
            self.sessmodel.objects.filter(user = userobj).delete()

        return self.sessmodel.objects.create(
            session_key = self.new_session_key(),
            expire_date = self.set_expiry(),
            user = userobj
        )

    def check_login(self, Session_key): #Methods: To login
        session = self.sessmodel.objects.filter(session_key=Session_key)
        if session.exists():
            if timezone.localdate() < session[0].expire_date:
                return session[0].user 
            else:
                session[0].delete()
                return False
        else:
            return False

    def logout(self, Session_key):
        session = self.sessmodel.objects.filter(session_key=Session_key)
        if session.exists():
            session[0].delete()
            return True
        else:
            return False
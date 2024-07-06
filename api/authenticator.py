from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ObjectDoesNotExist
from .models import MGRealm

class CustomerManager(ModelBackend):
    # For Authentication with mail
    def authenticatemail(self, _email=None, password=None):
        if _email is None or password is None:
            return
        try:
            user = MGRealm.objects.get(email=_email)
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
            else:
                return None
        except ObjectDoesNotExist:
            return None
    
    # For authentication with username
    def authenticateusername(self, _username=None, password=None):
        print(_username, password)
        if _username is None or password is None:
            print("exit1")
            return
        try:
            user = MGRealm.objects.get(username=_username)
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
            else:
                print("exit2")
                return None
        except ObjectDoesNotExist:
            print("exit3")
            return None
        
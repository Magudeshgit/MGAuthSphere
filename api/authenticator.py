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
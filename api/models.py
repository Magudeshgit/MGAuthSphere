from django.db import models
from django.contrib.auth.models import User, PermissionsMixin, Permission, UserManager
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import AbstractUser, User, Group
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta, datetime
from django.utils.crypto import get_random_string
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.sessions.base_session import BaseSessionManager
from django.contrib.auth.hashers import make_password
import string

VALID_KEY_CHARS = string.ascii_lowercase + string.digits

class MG_Products(models.Model):
    productname = models.CharField(max_length=50)
    description = models.TextField()
    version = models.FloatField()
    
    class Meta:
        verbose_name = "MGRealm Product"
        verbose_name_plural = "MGRealm Products"

    def __str__(self):
        return self.productname

class MGRealm(AbstractUser):
    developer = models.BooleanField(default=False)
    signed_services=models.ManyToManyField(MG_Products, related_name='signedservices')
    api_token = models.CharField(max_length=100, blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="mguser_set")
    groups = None

    def save(self, *args, **kwargs):
        if not self.pk:
            default_mgproduct = MG_Products.objects.get(productname="MGRealm")
            self.signed_services = default_mgproduct
            self.password = make_password(self.password)
            return super().save(*args, **kwargs)
        
        if self.developer:
            if self.api_token == '':
                api_token = Token.objects.create(user = self)
                self.api_token = api_token.key
        else:
            self.api_token = ''

        return super().save(*args, **kwargs)

    def __str__(self):
        return self.username
    
    class Meta:
        verbose_name="MGRealm Account"
        verbose_name_plural="MGRealm Accounts"

class MGRealm_Sessions(models.Model):
    session_key = models.CharField(max_length=40, primary_key=True)
    created_on = models.DateTimeField(default=datetime.now())
    expire_date = models.DateField(db_index=True)
    user = models.ForeignKey(MGRealm, on_delete=models.CASCADE)

    def __str__(self):
        return self.session_key    
    
    class Meta:
        verbose_name = "MGRealm_Session"
        verbose_name_plural = "MGRealm_Sessions"
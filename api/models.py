from django.db import models
from django.contrib.auth.models import AbstractUser, Group, User, PermissionsMixin, Permission, UserManager
from rest_framework.authtoken.models import Token
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta, datetime
from django.utils.crypto import get_random_string
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.sessions.base_session import BaseSessionManager
from django.core.validators import validate_email
from django.contrib.auth.hashers import make_password
from cryptography.fernet import Fernet
from .modelmanager import CustomManager
import string
import uuid

VALID_KEY_CHARS = string.ascii_lowercase + string.digits

# Note:
# Two types of tokens are used for authorization
# 1.) app_key in MG_Products - For internal authorization between MG apps within MGAuthSphere
# 2.) api_token in MGRealm - For Developer access to mgauthsphere itself

class MG_Products(models.Model):
    productname = models.CharField(max_length=50)
    description = models.TextField()
    version = models.FloatField()
    app_key = models.CharField(max_length=50, blank=True, verbose_name='App key (autogenerated)')
    
    # Encryption
    symkey = models.CharField(max_length=100, blank=True, null=True)
    pubkey = models.CharField(max_length=100, blank=True, null=True)
    prvkey = models.CharField(max_length=100, blank=True, null=True)
    
    
    def save(self, *args, **kwargs):
        if self.pk is None:
            print("TEST")
            self.app_key = get_random_string(length=32)
            self.symkey = Fernet.generate_key().decode()
        return super().save(*args, **kwargs)
            
    
    class Meta:
        verbose_name = "MG Service Account"
        verbose_name_plural = "MG Service Accounts"

    def __str__(self):
        return self.productname

class MGRealm(AbstractUser):
    email = models.EmailField(unique=True, validators=[validate_email])
    userid = models.CharField(max_length=50, null=True, blank=True)
    developer = models.BooleanField(default=False)
    signed_services=models.ManyToManyField(MG_Products, related_name='signedservices')
    user_permissions = models.ManyToManyField(Permission, related_name="mguser_set")
    groups = None
    username = None
    
    created_service = models.CharField(max_length=50, blank=True)
    api_token = models.CharField(max_length=100, blank=True, verbose_name="Developer Token")    #For Developer Allowance
    oauth_credentials = models.JSONField(blank=True, null=True)
    
    is_oauth = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    
    
    objects = CustomManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        if self.pk is None:
            self.userid = str(uuid.uuid4()).replace('-','')
        if not self.password.startswith("pbkdf2_sha256$"):
            self.password = make_password(self.password)
        return super().save(*args, **kwargs)
    
    class Meta:
        verbose_name="User Account"
        verbose_name_plural="User Accounts"

class MGRealm_Sessions(models.Model):
    session_key = models.CharField(max_length=40, primary_key=True)
    created_on = models.DateTimeField(default=datetime.now())
    expire_date = models.DateField(db_index=True)
    user = models.ForeignKey(MGRealm, on_delete=models.CASCADE)

    def __str__(self):
        return self.session_key    
    
    class Meta:
        verbose_name = "User Account Session"
        verbose_name_plural = "User Account Sessions"
        

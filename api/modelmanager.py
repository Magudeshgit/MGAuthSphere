from typing import Any
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.hashers import make_password

class CustomManager(BaseUserManager):
    print("Custom")
    def create_user(self,username=None, email=None,password=None,**extra_fields):
        print("asdad", email, password)
        if not email:
            raise ValueError("Email field should not be empty")
        user = self.model(email = email, username=username)
        user.password = make_password(password)
        user.is_active = True
        user.save(using=self._db)
        return user
    
    def create_superuser(self,username=None, email=None,password=None,**extra_fields):
        if not email:
            raise ValueError("Email field should not be empty")
        user = self.create_user(email=email,password=password, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)
        return user
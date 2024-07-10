from typing import Any
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.hashers import make_password

class CustomManager(BaseUserManager):
    use_in_migrations = True
    def create_user(self,email,password,**extra_fields):
        if not email:
            raise ValueError("Email field should not be empty")
        user = self.model(email = email)
        user.password = make_password(password)
        user.is_active = True
        user.save(using=self._db)
        return user
    
    def create_superuser(self,email=None,password=None,**extra_fields):
        if not email:
            raise ValueError("Email field should not be empty")
        user = self.create_user(email=email,password=password, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)
        return user
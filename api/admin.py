from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.sessions.models import Session
from .models import MGRealm, MG_Products, MGRealm_Sessions


admin.site.register([MGRealm,MG_Products, MGRealm_Sessions])
admin.site.unregister(Group)
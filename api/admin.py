from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.models import Group, Permission
from django.contrib.sessions.models import Session
from .models import MGRealm, MG_Products, MGRealm_Sessions

admin.site.site_header = 'MGAuthSphere'
admin.site.site_title = 'MGAuthSphere'
admin.site.index_title = 'MGRealm Administration'

admin.site.register([MGRealm,MG_Products, MGRealm_Sessions, Permission])
admin.site.unregister(Group)
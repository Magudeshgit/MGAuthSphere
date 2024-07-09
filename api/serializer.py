from rest_framework import serializers
from api.models import MGRealm, MGRealm_Sessions, MG_Products

class services_Serializer(serializers.ModelSerializer):
	class Meta:
		model = MG_Products
		fields = ['productname', 'version']

class Account_Serializer(serializers.ModelSerializer):
	signed_services = services_Serializer(many=True, read_only=True)	
	class Meta:
		model=MGRealm
		fields=['id','email','signed_services']



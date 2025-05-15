import firebase_admin.app_check
import firebase_admin.auth
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import action, authentication_classes, permission_classes
from rest_framework.viewsets import ModelViewSet
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.conf import settings

from .models import MGRealm, MG_Products
from .authenticator import CustomerManager as cm
from .serializer import Account_Serializer
from .session_handler import SessionHandler
from .requestutility import exchange_token

import firebase_admin
import os

cred = firebase_admin.credentials.Certificate(os.path.join(settings.BASE_DIR,'api/firebase.json'))
firebpp = firebase_admin.initialize_app(cred)


@authentication_classes([SessionAuthentication,TokenAuthentication])
@permission_classes([IsAuthenticated])
# @csrf_exempt

class Public_Accounts(ModelViewSet):
    serializer_class = Account_Serializer
    queryset = MGRealm.objects.all()
    sh = SessionHandler()
    at = cm()

    @action(detail=False, methods=['post'])
    # UPDATE 25-06-24: Determine from which app "/creatuser/" request is received and then handle signed_services accordingly.
    def createuser(self, request):
        try: 
            Email = request.data['email']
            Password = request.data['password']
            App_key = request.data['app_key']
        except KeyError:
            return Response("InvalidParameters: Parameters are invalid or missing (Required parameters: email,password, app_password)", status=status.HTTP_400_BAD_REQUEST)
        
        _optional_fields = ['first_name','last_name']
        optional_fields = {'first_name': '', 'last_name': ''}
        for field in _optional_fields:
            if request.data.get(field) != None:
                optional_fields[field] = request.data.get(field)
        
        
        response = self._create_user(Email, Password, App_key, **optional_fields)    
        return Response(response)
    
    @action(detail=False, methods=['post'])
    def authenticate(self, request): #To handle login
        try: 
            Email = request.data['email']
            Password = request.data['password']
        except KeyError:
            return Response("InvalidParameters: Parameters are invalid or missing (Required parameters: email,password)", status=status.HTTP_400_BAD_REQUEST)

        user = self.at.authenticatemail(_email=Email, password=Password)
        if user is not None:
            # Session allocation
            session = self.sh.create_session(user_id=user.id)
            respond = Account_Serializer(user).data
            respond['status'] = 'success'
            respond['session_id'] = session.session_key
            respond['session_expiry'] = session.expire_date
            return Response(respond)
        else:
            respond = {'status': 'failed', 'detail': 'User does not exist'}
            return Response(respond, status=status.HTTP_401_UNAUTHORIZED)
    
    @action(detail=False, methods=['post'])
    def checklogin(self, request):
        try:
            Session_id = request.data['session_id']
        except KeyError:
            return Response({"status":"failed","detail":"InvalidParameters: Parameters are invalid or missing (Required parameters: session id)"}, status=status.HTTP_400_BAD_REQUEST)
        user = self.sh.check_login(Session_id)
        if user:
            respond = Account_Serializer(user).data
            respond['status'] = 'success'
            respond['session_id'] = Session_id
            return Response(respond)
        else:
            return Response({"status": "failed","detail": "User Session does not exist: Authenticate first"}, status=status.HTTP_401_UNAUTHORIZED)
    
    @action(detail=False, methods=['post'])        
    def getsymmetrickey(self, request):
        try:
            app_key = request.data['app_key']
            key = MG_Products.objects.get(app_key=app_key).symkey
        except Exception:
            return Response({"status":"failed","detail": "InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"status":"success","symkey": key})
    
    @action(detail=False, methods=['post'])        
    def logout(self, request):
        try:
            Session_id = request.data['session_id']
        except KeyError:
            return Response({"status":"failed","detail": "InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)"}, status=status.HTTP_400_BAD_REQUEST)
        
        if self.sh.logout(Session_id):
            return Response({"status":"success","detail": "logout operation succesfull"})
        else:
            return Response({"status":"failed","detail": "unsuccesfull"})
        
        # Primary Update 1: Adding Oauth Provision
    
    # @action (detail=False, methods=['post'])
    # def gauth_validate(detAI)
    
    @action(detail=False, methods=['post'])
    def oauthcreateuser(self, request):
        MGRealm.objects.update()
        
        try:
            id__token = request.data['id_token']
            refresh__token = request.data['refresh_token']
            k = firebase_admin.auth.verify_id_token(id__token)
            print(k)
            _optional_fields = {"first_name": k['name'],  
                               "oauth_credentials": {
                                   "refreshToken": refresh__token,
                                   "uid": k['uid'],
                                   "sign_in_provider": k['firebase']['sign_in_provider'],
                                   "photoURL": k['picture']
                               },
                               "is_oauth": True,
                               "is_email_verified": k['email_verified']
                               }
            response = self._create_user(k['email'], k['email']+k['name'], request.data['app_key'], **_optional_fields)
    
            return Response(response)
        
        
        except KeyError:
            return Response({"status":"failed","detail": "InvalidParameters: Parameters are invalid or missing (Required parameters: id_token, refresh_token)"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "failed", "detail": f"as{e}"})
    
    @action(detail=False, methods=['post'])
    def oauth_checklogin(self, request):
        try: 
            session_id = request.data['session_id']
            user = self.sh.get_corresponding_user(session_id)
            if user  == False:
                return Response({"status": "failed", "detail": "Invalid session_id"})
            else:
                # k = firebase_admin.credentials.RefreshToken(user.oauth_credentials['refreshToken'])
                k=exchange_token(user.oauth_credentials['refreshToken'])
                _user_profile = k['user_profile']
                self.revise_oauth_user_profile(user,_user_profile)
                return Response({"status": "success", "detail": k})
        except KeyboardInterrupt as e:
            print(e)
            return Response({"status": "failed", "detail": f"Invalid Token {e}"}, status=status.HTTP_401_UNAUTHORIZED)
            

                
            
            
    
    
    # Utility Functions
    def _create_user(self, email, password, appId, **optional_fields):
        try:
            app = MG_Products.objects.get(app_key=appId)
            user = MGRealm.objects.create_user(email=email, password=password, created_service=app.productname, **optional_fields)
            user.signed_services.add(app)
            user.save()
            
        except Exception as e:
            return {"status": "failed", "detail": str(e)}

        # Session Allocation
        session = self.sh.create_session(user_id=user.id)
        respond = Account_Serializer(user).data
        respond['session_id'] = session.session_key
        respond['session_created'] = session.created_on
        respond['session_expiry'] = session.expire_date
        
        return respond
    
    def revise_oauth_user_profile(self, user, updated_details):
        
        user.first_name = updated_details['name']
        user.oauth_credentials['photoURL'] = updated_details['picture']
        user.save()
        
        return True
    
    # Done with implementing redundanct between GL Servers and MGAS, but need to reform architure in such a way MGAS stays APEX for authenticated users, Any action relating to user access control shall only resort to MGAS as endpoint.  - PENDING UPDATE

        
        
    
    def get_view_name(self):
        return 'MGAuthSphere - Central Authentication'

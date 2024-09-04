from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import action, authentication_classes, permission_classes
from rest_framework.viewsets import ModelViewSet
from .models import MGRealm, MG_Products
from .authenticator import CustomerManager as cm
from .serializer import Account_Serializer
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .session_handler import SessionHandler
from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt


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
                
        try:
            app = MG_Products.objects.get(app_key=App_key)
            user = MGRealm.objects.create_user(email=Email, password=Password, created_service=app.productname, **optional_fields)
            user.signed_services.add(app)
            user.save()
        except (IntegrityError, ObjectDoesNotExist) as e:
            return Response({"status": "failed", "detail":str(e)})

        # Session Allocation
        session = self.sh.create_session(user_id=user.id)
        respond = Account_Serializer(user).data
        respond['status'] = 'success'
        respond['session_id'] = session.session_key
        respond['session_created'] = session.created_on
        respond['session_expiry'] = session.expire_date
        
        return Response(respond)

    
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
    def logout(self, request):
        try:
            Session_id = request.data['session_id']
        except KeyError:
            return Response({"status":"failed","detail": "InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)"}, status=status.HTTP_400_BAD_REQUEST)
        
        if self.sh.logout(Session_id):
            return Response({"status":"success","detail": "logout operation succesfull"})
        else:
            return Response({"status":"failed","detail": "unsuccesfull"})
    
    def get_view_name(self):
        return 'MGAuthSphere - Central Authentication'
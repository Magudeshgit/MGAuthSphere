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

@authentication_classes([SessionAuthentication,TokenAuthentication])
@permission_classes([IsAuthenticated])
class Public_Accounts(ModelViewSet):
    serializer_class = Account_Serializer
    queryset = MGRealm.objects.all()
    sh = SessionHandler()
    at = cm()

    @action(detail=False, methods=['post'])
    # UPDATE 25-06-24: Determine from which app "/creatuser/" request is received and then handle signed_services accordingly.
    def createuser(self, request):
        try: 
            Username = request.data['username']
            Password = request.data['password']
            App_key = request.data['app_key']
        except KeyError:
            return Response("InvalidParameters: Parameters are invalid or missing (Required parameters: username,password, app_password)", status=status.HTTP_400_BAD_REQUEST)
        
        _optional_fields = ['first_name','last_name','email']
        optional_fields = {'first_name': '', 'last_name': '', 'email': ''}
        for field in _optional_fields:
            if request.data.get(field) != None:
                optional_fields[field] = request.data.get(field)
                
        try:
            app = MG_Products.objects.get(app_key=App_key)
            user = MGRealm.objects.create(username=Username, password=Password, created_service=app.productname, **optional_fields)
            user.signed_services.add(app)
            user.save()
        except (IntegrityError, ObjectDoesNotExist) as e:
            return Response({"status": "failed", "detail":str(e)})

        # Session Allocation
        session = self.sh.create_session(user_id=user.id)
        respond = Account_Serializer(user).data
        respond['session_id'] = session.session_key
        return Response(respond)

    
    @action(detail=False, methods=['post'])
    def authenticate(self, request): #To handle login
        print(request.user)
        Mode = ''
        try: 
            Mode = request.data['authmode']
            if Mode == 'alpha':
                Email = request.data['email']
            else:
                Username = request.data['username']
            Password = request.data['password']
        except KeyError:
            return Response("InvalidParameters: Parameters are invalid or missing (Required parameters: username,password,authmode)", status=status.HTTP_400_BAD_REQUEST)
        
        if Mode == 'alpha':
            user = self.at.authenticatemail(_email=Email, password=Password)
        else:
            user = self.at.authenticateusername(_username=Username, password=Password)
        if user is not None:
            # Session allocation
            session = self.sh.create_session(user_id=user.id)
            respond = Account_Serializer(user).data
            respond['session_id'] = session.session_key
            print(respond)
            return Response(respond)
        else:
            return Response("User does not Exist", status=status.HTTP_401_UNAUTHORIZED)
    
    @action(detail=False, methods=['post'])
    def checklogin(self, request):
        try:
            Session_id = request.data['session_id']
        except KeyError:
            return Response({"status":"failed","detail":"InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)"}, status=status.HTTP_400_BAD_REQUEST)
        user = self.sh.check_login(Session_id)
        if user:
            respond = Account_Serializer(user).data
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
            return Response({"detail": "Succesfull"})
        else:
            return Response({"detail": "Unsuccesfull"})
        
    @action(detail=False, methods=['post'])  
    def sample(self, request):
        a=request.data.get('no')
        b=request.data.get('sdf')
        print(a,b)
        return Response("Hello!")


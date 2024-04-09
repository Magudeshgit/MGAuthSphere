from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import action, authentication_classes, permission_classes
from rest_framework.viewsets import ModelViewSet
from .models import MGRealm
from django.contrib.auth import authenticate
from .serializer import Account_Serializer
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .session_handler import SessionHandler
from django.db.utils import IntegrityError

@authentication_classes([SessionAuthentication,TokenAuthentication])
@permission_classes([IsAuthenticated])
class Public_Accounts(ModelViewSet):
    serializer_class = Account_Serializer
    queryset = MGRealm.objects.all()
    sh = SessionHandler()

    @action(detail=False, methods=['post'])
    def createuser(self, request):
        try: 
            Username = request.data['username']
            Password = request.data['password']
        except KeyError:
            return Response("InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)", status=status.HTTP_400_BAD_REQUEST)
        try:
            user = MGRealm.objects.create(username=Username, password=Password)
        except IntegrityError:
            return Response("User already exists")
        print('asdd',user)
        session = self.sh.create_session(user_id=user.id)
        respond = Account_Serializer(user).data
        respond['session_id'] = session.session_key
        return Response(respond)

    
    @action(detail=False, methods=['post'])
    def authenticate(self, request): #To handle login
        print(request.user)
        try: 
            Username = request.data['username']
            Password = request.data['password']
        except KeyError:
            return Response("InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)", status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=Username, password=Password)
        print(user)
        if user is not None:
            print('saas',user.id)
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
            return Response({"Detail":"InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)"}, status=status.HTTP_400_BAD_REQUEST)
        user = self.sh.check_login(Session_id)
        if user:
            respond = Account_Serializer(user).data
            respond['session_id'] = Session_id
            return Response(respond)
        else:
            return Response({"Detail": "User Session does not exist: Authenticate first"}, status=status.HTTP_401_UNAUTHORIZED)

    @action(detail=False, methods=['post'])        
    def logout(self, request):
        try:
            Session_id = request.data['session_id']
        except KeyError:
            return Response({"Detail": "InvalidParameters: Parameters are invalid or missing (Required parameters: username,password)"}, status=status.HTTP_400_BAD_REQUEST)
        if self.sh.logout(Session_id):
            return Response({"Detail": "Succesfull"})
        else:
            return Response({"Detail": "Unsuccesfull"})


import django.conf
import stream_chat
from django.shortcuts import render, redirect
from datetime import datetime, timedelta
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from Abonnement.models import PackageSerializer, Package, Abonnement, AbonnementSerializer, UserSerializer


class PackageView(ListAPIView):
    queryset = Package.objects.filter(active=True)
    serializer_class = PackageSerializer
    authentication_classes = []
    pass


class PackageGetView(RetrieveAPIView):
    queryset = Package.objects.filter(active=True)
    serializer_class = PackageSerializer
    authentication_classes = []
    pass


class AbonnementLiyeplimalView(APIView):
    authentication_classes = [JSONWebTokenAuthentication]

    def post(self, request, **kwargs):
        try:
            sub = Abonnement.objects.get(user=request.user)
            if request.data.get('action') == 'delete':
                sub.active = False
                sub.save()
                return Response({
                    "status": 1,
                    "message": "Souscription revoqué"
                })
            elif request.data.get('action') == 'update':
                sub.pack_id = request.data.get('pack')
                sub.transaction = request.data.get('transaction')
                sub.gateway = request.data.get('gateway')
                sub.status = 'P'
                sub.subdate = datetime.now()
                sub.expdate = datetime.now() + timedelta(days=30)
                sub.save()
                return Response({
                    "status": 0,
                    "message": "Souscription mise à jour"
                })
            else:
                if sub.active:
                    return Response({
                        "status": 1,
                        "message": "Vous avez déjà un abonnement actif"
                    })
                else:
                    sub.pack_id = request.data.get('pack')
                    sub.transaction = request.data.get('transaction')
                    sub.gateway = request.data.get('gateway')
                    sub.subdate = datetime.now()
                    sub.status = 'P'
                    sub.active = True
                    sub.expdate = datetime.now() + timedelta(days=30)
                    sub.save()
                    return Response({
                        "status": 0,
                        "message": "Vous abonnement a été mise à jour"
                    })
        except Abonnement.DoesNotExist:
            sub = Abonnement.objects.create(
                user=request.user, pack_id=request.data.get('pack'),
                transaction=request.data.get('transaction'), active=True,
                status="P", expdate=(datetime.now() + timedelta(days=30)), gateway=request.data.get('gateway')
            )
            sub.save()
            return Response({
                "status": 0,
                "message": "Souscription effectué avec succès"
            })
        except Exception as e:
            return Response({
                "status": -1,
                "message": "La souscription n'a pas abouti"
            }, 400)
        pass

    def delete(self, request, **kwargs):
        try:
            sub = Abonnement.objects.get(user=request.user, active=True)
            sub.active = False
            sub.save()
            return Response({
                "status": 1,
                "message": "Souscription revoqué"
            })
        except Abonnement.DoesNotExist:
            return Response({
                "status": 0,
                "message": "Aucun abonnement actif"
            })

    def get(self, request, **kwargs):
        try:
            sub = Abonnement.objects.get(user=request.user, active=True)
            return Response({
                "status": 0,
                "pack": AbonnementSerializer(sub, many=False).data
            })
        except Abonnement.DoesNotExist:
            return Response({
                "status": -1,
                "message": "Aucun Abonnement actif"
            })
        pass


class ChatView(APIView):
    authentication_classes = [JSONWebTokenAuthentication]

    def post(self, request, **kwargs):
        try:
            Abonnement.objects.get(user=request.user, active=True, status='A')
            server_client = stream_chat.StreamChat(api_key="k4kear464def",
                                                   api_secret="wdstgq46zn8ff44j2w9q4zh89ynvybgpxye5eeqg834mqxs2kegwkq3mw6kqxg24")
            token = server_client.create_token(str(request.user.id), exp=datetime.utcnow() + timedelta(hours=1))
            return Response({
                'token': token
            })
        except Abonnement.DoesNotExist:
            return Response({}, 200)
        pass


class AdminView(APIView):
    authentication_classes = [JSONWebTokenAuthentication]

    def post(self, request, **kwargs):
        if request.user.is_staff:
            server_client = stream_chat.StreamChat(api_key="k4kear464def",
                                                   api_secret="wdstgq46zn8ff44j2w9q4zh89ynvybgpxye5eeqg834mqxs2kegwkq3mw6kqxg24")
            token = server_client.create_token(str(request.user.id), exp=datetime.utcnow() + timedelta(hours=1))
            return Response({
                'token': token,
                'user': UserSerializer(request.user, many=False).data
            })
        else:
            return Response({}, 200)
        pass


def index(request):
    return redirect(django.conf.settings.HOME_URL)

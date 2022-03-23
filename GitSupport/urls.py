"""GitSupport URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.urlpatterns import format_suffix_patterns
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token, verify_jwt_token
from Abonnement.views import PackageView, index, PackageGetView, AbonnementLiyeplimalView, ChatView, AdminView

urlpatterns = [

    path('admin/', admin.site.urls),
    path('tinymce/', include('tinymce.urls')),

    path('accounts/', include('django.contrib.auth.urls')),
    path('account/', include('allauth.account.urls')),
    path('account/', include('allauth.urls')),

    path('auth/', include('rest_auth.urls')),
    path('auth/register/', include('rest_auth.registration.urls')),

    path('jwt/token/', obtain_jwt_token),
    path('jwt/refresh/', refresh_jwt_token),
    path('jwt/verify/', verify_jwt_token),

    path('api/subscribe/0/', AbonnementLiyeplimalView.as_view()),
    path('api/chat/token/', ChatView.as_view()),
    path('api/admin/token/', AdminView.as_view()),

    path('api/package/', PackageView.as_view()),
    path('api/package/<pk>/', PackageGetView.as_view()),
    path('', index)

]

urlpatterns = format_suffix_patterns(urlpatterns)

urlpatterns += staticfiles_urlpatterns()

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

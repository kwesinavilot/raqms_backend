from .views import *
from django.urls import path, include
from rest_framework.authtoken import views

urlpatterns = [
    path('register/', registerUser, name='register'),
    path('login/', loginUser, name='login'),
    path('logout/', logoutUser, name='logout'),
    path('token/', views.obtain_auth_token),
    path('reset-password/request/', passwordResetRequest, name='reset-password-request'),
    path('reset-password/verify/', verifyPasswordResetToken, name='verify-reset-token'),
    path('reset-password/reset/', resetPassword, name='reset-password'),
    # path('google/callback', handleGoogleAuth, name='gauth')
]
from django.shortcuts import render
from .serializers import *
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getHourlyForecast(request):
    pass


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getWeeklyForecast(request):
    pass
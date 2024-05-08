from .utils import getLatestClarityReadings
from .serializers import *
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def getLocationAQ(request):
    # get user's current location from request
    longitude = request.data.get('longitude')
    latitude = request.data.get('latitude')

    if longitude is None or latitude is None:
        return Response({"error": "User's current location is needed!"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # get latest readings from Clarity
        currentReadings = getLatestClarityReadings('AYX3T9JH')

        # save the readings to the database
        AQReadings.objects.create(
            user=request.user, 
            latitude=latitude, 
            longitude=longitude, 
            pm25=currentReadings['measurements']['pm25'], 
            overallAQI=currentReadings['overallAQI'],
            recordTime=currentReadings['time'],

            # if they exist, save them
            pm1=currentReadings['measurements']['pm1'] if 'pm1' in currentReadings['measurements'] else None,
            pm10=currentReadings['measurements']['pm10'] if 'pm10' in currentReadings['measurements'] else None,
            no2=currentReadings['measurements']['no2'] if 'no2' in currentReadings['measurements'] else None,
            humidity=currentReadings['measurements']['humidity'] if 'humidity' in currentReadings['measurements'] else None,
            temperature=currentReadings['measurements']['temperature'] if 'temperature' in currentReadings['measurements'] else None,
        )
    except Exception as exception:
        return Response({"error": "Could not get the air quality readings in your location!" + str(exception)}, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(currentReadings, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def exposureHistory(request):
    "Get the user's air quality exposure history"

    # get the user from the request
    user = request.user

    history = AQReadings.objects.filter(user=user).order_by('-recordTime')
    # print(history)

    historySerializer = AQHistorySerializer(history, many=True)

    return Response(historySerializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getAllExposureHistory(request):
    "Get all air quality exposure history"

    history = AQReadings.objects.all().order_by('-recordTime')
    # print(str(history))

    historySerializer = AQReadingsSerializer(history, many=True)

    return Response(historySerializer.data, status=status.HTTP_200_OK)
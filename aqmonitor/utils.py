import requests
import json
import datetime
import os
from .aqi_calculator_us import calculateAQI
from accounts.utils import sendSMS

def getLatestClarityReadings(deviceID):
    print("Fetching data from Clarity...")
    
    # Get Clarity credentials from environment variable
    org = os.environ.get('CLARITY_ORG')
    apiKey = os.environ.get('CLARITY_API_KEY')

    # Calculate start and end time
    endDate = datetime.datetime.now().isoformat()
    startDate = (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat()

    # Set headers for fetch request
    headers = {
        'x-api-key': apiKey,
        'Accept-Encoding': 'gzip'
    }

    # Fetch data from external API
    response = requests.get(f"https://clarity-data-api.clarity.io/v1/measurements?code={deviceID}&limit=1&startTime={startDate}&endTime={endDate}&org={org}", headers=headers)
    data = response.json()

    if data:
        # Extract measurement values into an object
        measurements = {
            'pm1': data[0]['characteristics']['pm1ConcNum']['value'],
            'pm25': data[0]['characteristics']['pm2_5ConcNum']['value'],
            'pm10': data[0]['characteristics']['pm10ConcNum']['value'],
            'no2': data[0]['characteristics']['no2Conc']['value'],
            'humidity': data[0]['characteristics']['relHumid']['value'],
            'temperature': data[0]['characteristics']['temperature']['value'],
        }

        # Calculate the Overall AQI based on defined standards
        overall_aqi = calculateAQI(measurements['pm1'], measurements['pm25'], measurements['pm10'], measurements['no2'])

        # Filter the data and add the extracted values and calculated AQI
        filteredData = {
            'time': datetime.datetime.fromisoformat(data[0]['time']).strftime('%Y-%m-%d %H:%M:%S'),
            'measurements': measurements,
            'overallAQI': overall_aqi
        }

        return filteredData
    else:
        # If data.measurements is empty, return an empty object or handle it as needed
        print('Clarity data is empty.')
        return []
    
def sendAQIAlert(phoneNumber, overallAQI):
    # craft the message
    message = f"""Hello, the air quality at your current location is {overallAQI}. Put on a nose mask!"""

    # send the message
    sendSMS(phoneNumber, message)
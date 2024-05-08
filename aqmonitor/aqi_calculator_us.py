# Pollutant-specific constants for AQI breakpoints and their corresponding concentrations
PM1_BREAKPOINTS = [12, 35.4, 55.4, 150.4, 250.4, 350.4, 500.4]
PM1_I_HIGH = [50, 100, 150, 200, 300, 400, 500]
PM1_I_LOW = [0, 51, 101, 151, 201, 301, 401]

PM25_BREAKPOINTS = [12.1, 35.5, 55.5, 150.5, 250.5, 350.5, 500.5]
PM25_I_HIGH = [50, 100, 150, 200, 300, 400, 500]
PM25_I_LOW = [0, 51, 101, 151, 201, 301, 401]

PM10_BREAKPOINTS = [54, 154, 254, 354, 424, 504, 604]
PM10_I_HIGH = [50, 100, 150, 200, 300, 400, 500]
PM10_I_LOW = [0, 51, 101, 151, 201, 301, 401]

NO2_BREAKPOINTS = [53, 100, 360, 649, 1249, 1649, 2049]
NO2_I_HIGH = [50, 100, 150, 200, 300, 400, 500]
NO2_I_LOW = [0, 51, 101, 151, 201, 301, 401]

# Function to calculate the AQI for a given pollutant concentration and breakpoints
def calculatePollutantAQI(concentration, breakpoints, iHigh, iLow):
    # Find the index of the highest breakpoint below the concentration
    index = 0
    while index < len(breakpoints) and concentration > breakpoints[index]:
        index += 1

    if index == 0:
        return round((iHigh[index] - iLow[index]) / (breakpoints[index] - 0) * (concentration - 0) + iLow[index])
    elif index == len(breakpoints):
        return iHigh[index - 1]
    else:
        return round((iHigh[index] - iLow[index]) / (breakpoints[index] - breakpoints[index - 1]) * (concentration - breakpoints[index - 1]) + iLow[index])

# Function to calculate the Overall AQI based on USA EPA standards
def calculateAQI(pm1=0, pm25=0, pm10=0, no2=0):
    # Validate input values
    pm1 = max(pm1, 0)
    pm25 = max(pm25, 0)
    pm10 = max(pm10, 0)
    no2 = max(no2, 0)

    # Calculate AQI for each pollutant
    aqiPM1 = calculatePollutantAQI(pm1, PM1_BREAKPOINTS, PM1_I_HIGH, PM1_I_LOW)
    aqiPM25 = calculatePollutantAQI(pm25, PM25_BREAKPOINTS, PM25_I_HIGH, PM25_I_LOW)
    aqiPM10 = calculatePollutantAQI(pm10, PM10_BREAKPOINTS, PM10_I_HIGH, PM10_I_LOW)
    aqiNO2 = calculatePollutantAQI(no2, NO2_BREAKPOINTS, NO2_I_HIGH, NO2_I_LOW)

    # Choose the highest AQI value calculated for each pollutant as the Overall AQI
    overallAQI = max(aqiPM1, aqiPM25, aqiPM10, aqiNO2)
    
    return overallAQI
from accounts.serializers import *
from .serializers import AuthSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from accounts.utils import generateUserID
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.authtoken.models import Token
from .utils import *
from .models import ResetToken
import datetime
# from dateutil import tz
from rest_framework import viewsets
from django.shortcuts import get_object_or_404
from rest_framework.decorators import action

@extend_schema(
    summary="Register User",
    parameters=[
        OpenApiParameter("name", type=str, location="query", description="The name of the user"),
        OpenApiParameter("email", type=str, location="query", description="The email of the user"),
        OpenApiParameter("password", type=str, location="query", description="The password of the user"),
        OpenApiParameter("industry", type=str, location="query", description="The industry of the user"),
        OpenApiParameter("organization", type=str, location="query", description="The organization of the user"),
        OpenApiParameter("size", type=str, location="query", description="The size of the organization"),
        OpenApiParameter("role", type=str, location="query", description="The role of the user in the organization"),
        OpenApiParameter("country", type=str, location="query", description="The country of the organization"),
        OpenApiParameter("interests", type=str, location="query", description="What the user wants to achieve using our product"),
        OpenApiParameter("referrer", type=str, location="query", description="How the user heard about us"),
        OpenApiParameter("agreeTerms", type=str, location="query", description="The user agrees to the terms and conditions"),
    ],
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The name of the user",
                },
                "email": {
                    "type": "string",
                    "description": "The email of the user",
                },
                "password": {
                    "type": "string",
                    "description": "The password of the user",
                },
                "industry": {
                    "type": "string",
                    "description": "The industry of the user",
                },
                "organization": {
                    "type": "string",
                    "description": "The organization of the user",
                },
                "size": {
                    "type": "string",
                    "description": "The size of the organization",
                },
                "role": {
                    "type": "string",
                    "description": "The role of the user in the organization",
                },
                "country": {
                    "type": "string",
                    "description": "The country of the organization",
                },
                "interests": {
                    "type": "string",
                    "description": "What the user wants to achieve using our product",
                },
                "referrer": {
                    "type": "string",
                    "description": "How the user heard about us",
                },
                "agreeTerms": {
                    "type": "string",
                    "description": "The user agrees to the terms and conditions",
                },
            },
            "example": {
                "name": "John Doe",
                "email": "johndoe@x.com",
                "password": "password123",
                "industry": "Technology",
                "organization": "Organization 1",
                "size": "1-10",
                "role": "Manager",
                "country": "USA",
                "interests": "Productivity",
                "referrer": "LinkedIn",
                "agreeTerms": "Yes",
            },
        }
    },
    responses={
        "200": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Success message",
                },
                "user": {
                    "type": "object",
                    "properties": {
                        "userID": {
                            "type": "integer",
                            "description": "The ID of the user",
                        },
                        "orgID": {
                            "type": "integer",
                            "description": "The ID of the organization",
                        },
                        "name": {
                            "type": "string",
                            "description": "The name of the user",
                        },
                        "email": {
                            "type": "string",
                            "description": "The email of the user",
                        },
                        "isAdmin": {
                            "type": "boolean",
                            "description": "Whether the user is an admin",
                        },
                    },
                },
                "token": {
                    "type": "string",
                    "description": "The token of the user",
                },
            },
            "example": {
                "message": "User registered and logged in successfully",
                "user": {
                    "userID": "UBU34ERE23",
                    "orgID": "UBOR34ER23",
                    "name": "John Doe",
                    "email": "johndoe@x.com",
                    "isAdmin": False,
                },
                "token": "1234567890abcdef",
            },
        },
        "400": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "Missing required fields: organization",
            },
        },
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def registerUser(request):
    """
    Register a new user and creates an organization and collects their insights.
    """

    # Validate required fields
    required_fields = ['firstName', 'lastName', 'phoneNumber']

    # Validate required fields using list comprehension
    missing_fields = [field for field in required_fields if field not in request.data]
    if missing_fields:
        return Response({'error': f'Missing required fields: {", ".join(missing_fields)}'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Additional validation for password length
    # try:
    #     validate_password(request.data.get('password'))
    # except ValidationError as e:
    #     return Response({'error': f'Invalid password: {e}'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if user already exists
    if User.objects.filter(phoneNumber=request.data.get('phoneNumber')).exists():
        return Response({'error': 'A user with this phone number already exists'}, status=status.HTTP_400_BAD_REQUEST)

    try:
            # Create user
        user = User.objects.create(
            userID=generateUserID(),
            firstName=request.data.get('firstName'),
            lastName=request.data.get('lastName'),
            phoneNumber=request.data.get('phoneNumber'),
        )

        # to create a password, extract the first 2 characters of the first and last names
        # and the last 4 digits of the phone number
        password = user.firstName[:2] + user.lastName[:2] + user.phoneNumber[-4:]

        user.set_password(password)
        user.save()

        # Log the user in
        login(request, user)

        # Get authentication token and user details
        newUser = AuthSerializer(user, many=False)

        # send an email
        # sendWelcomeEmailTask.delay(newUser.data['email'], newUser.data['name'])

        # Return token and user details in response
        return Response({
            'message': 'User registered and logged in successfully',
            'user': newUser.data,
            'token': Token.objects.get(user=user).key
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'error': f'Failed to create user: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    summary="Login User",
    parameters=[
        OpenApiParameter("email", type=str, location="query", description="Email of the user"),
        OpenApiParameter("password", type=str, location="query", description="Password of the user"),
    ],
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "description": "Email of the user",
                },
                "password": {
                    "type": "string",
                    "description": "Password of the user",
                },
            },
            "example": {
                "email": "johndoe@x.com",
                "password": "password123",
            },
        }
    },
    responses={
        "200": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Success message",
                },
                "user": {
                    "type": "object",
                    "properties": {
                        "userID": {
                            "type": "integer",
                            "description": "The ID of the user",
                        },
                        "orgID": {
                            "type": "integer",
                            "description": "The ID of the organization",
                        },
                        "name": {
                            "type": "string",
                            "description": "The name of the user",
                        },
                        "email": {
                            "type": "string",
                            "description": "The email of the user",
                        },
                        "isAdmin": {
                            "type": "boolean",
                            "description": "Whether the user is an admin",
                        },
                    },
                },
                "token": {
                    "type": "string",
                    "description": "The authentication token",
                },
            },
            "example": {
                "message": "User logged in successfully",
                "user": {
                    "userID": "UBU34ERE23",
                    "orgID": "UBOR34ER23",
                    "name": "John Doe",
                    "email": "johndoe@x.com",
                    "isAdmin": False,
                },
                "token": "1234567890abcdef",
            },
        },
        "400": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "Invalid email or password",
            },
        },
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def loginUser(request):
        """
        Extracts email and password from request data, validates them, finds the user by email,
        checks if the user is blocked, authenticates the user, and returns the token and user details in the response.
        """
        # check if user is logged in already
        if request.user.is_authenticated:
            return Response({'error': 'User is already logged in'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract email and password from request data
        phoneNumber = request.data.get('phoneNumber')
        password = request.data.get('password')

        # Validate email and password
        if not phoneNumber or not password:
            return Response({'error': 'The phone number is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Find user by email
        try:
            user = User.objects.get(phoneNumber=phoneNumber)

            # Check if user is blocked
            if user.isBlocked:
                return Response({'error': 'User is blocked for too many failed login attempts'}, status=status.HTTP_401_UNAUTHORIZED)
            
            # construct the user's password
            password = user.firstName[:2] + user.lastName[:2] + user.phoneNumber[-4:]

            # Authenticate user
            authUser = authenticate(phoneNumber=phoneNumber, password=password)

            if authUser:
                login(request, authUser)
                
                serializedUser = AuthSerializer(authUser, many=False)
                token, _ = Token.objects.get_or_create(user=user)

                # Return token and user details in response
                return Response({
                    'message': 'User logged in successfully',
                    'user': serializedUser.data,
                    'token': token.key
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_401_UNAUTHORIZED)
        
@extend_schema(
    summary="Logout User",
    parameters=None,
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The user's authentication token",
                },
            },
            "example": {
                "token": "1234567890abcdef",
            },
        }
    },
    responses={
        "200": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Success message",
                },
            },
            "example": {
                "message": "User logged out successfully",
            },
        },
        "400": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "message": "No authentication token provided",
            },
        },
        "500": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "message": "Something went wrong",
            },
        },
    },
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logoutUser(request):
    """
    Logs out the user and returns a success message in the response.
    """

    # check if a user is in the request and the user is authenticated
    if not request.user.is_authenticated:
        return Response({'message': 'No authentication token provided'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        request.user.auth_token.delete()
        
        return Response({'message': 'User logged out successfully'}, status=status.HTTP_200_OK)
    except Exception as exception:
        return Response({'message': 'Something went wrong: ' + str(exception)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema(
    summary="Request Password Reset",
    parameters=[
        OpenApiParameter("email", str, OpenApiParameter.QUERY, description="The user's email"),
    ],
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "description": "The user's email",
                },
            },
            "example": {
                "email": "johndoe@x.com",
            },
        }
    },
    responses={
        "200": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Success message",
                },
            },
            "example": {
                "message": "Password reset email sent",
            },
        },
        "400": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "message": "User's email is required",
            },
        },
        "404": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "message": "User not found",
            },
        },
        "500": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "message": "Something went wrong",
            },
        },
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def passwordResetRequest(request):
  """
  Sends a password reset email to the user's email. The reset email will contain a link with the email and hashed token.
  Clicking the link should redirect the user to a password reset form on the website (possible URL: auth/reset-password/verify).
  """
  # 1. Get the email from the request
  email = request.data.get("email")

  if not email:
    return Response({"message": "User's email is required"}, status=status.HTTP_400_BAD_REQUEST)

  # 2 find the user
  try:
    user = User.objects.get(email=email)
  except User.DoesNotExist:
    return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

  # 2. Generate and save a Password Reset Token 
  resetToken = saveResetToken(user, generateSecureToken())

  # 3. Send Reset Email
#   sendPasswordResetRequestEmailTask.delay(email, resetToken)

  return Response({"message": "Password reset email sent"}, status=status.HTTP_200_OK)

@extend_schema(
    summary="Verify Password Reset Token",
    parameters=[
        OpenApiParameter("email", str, OpenApiParameter.QUERY, description="The user's email"),
        OpenApiParameter("token", str, OpenApiParameter.QUERY, description="The password reset token"),
    ],
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "description": "The user's email",
                },
                "token": {
                    "type": "string",
                    "description": "The password reset token",
                },
            },
            "example": {
                "email": "johndoe@x.com",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            },
        }
    },
    responses={
        "200": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Success message",
                },
                "userID": {
                    "type": "string",
                    "description": "The user's ID",
                },
            },
            "example": {
                "message": "Token is valid",
                "userID": "UBUDF8WEDK23",
            },
        },
        "400": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "User's email is required",
            },
        },
        "404": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "User not found",
            },
        },
        "500": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "Something went wrong",
            },
        },
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def verifyPasswordResetToken(request):
  """
    Verifies the validity of the password reset token and/or URL.
    The token is valid for 3 hours.
  """
  email = request.data.get("email")
  resetToken = request.data.get("token")

  if not resetToken:
    return Response({"message": "Reset token is required"}, status=status.HTTP_400_BAD_REQUEST)

  if not email:
    return Response({"message": "User's email is required"}, status=status.HTTP_400_BAD_REQUEST)
  
  try:
    # get the associated user
    user = User.objects.get(email=email)
    
    # get the token
    resetToken = ResetToken.objects.get(user=user, token=resetToken)

    now = datetime.datetime.now(tz=tz.tzlocal())
    expirationTime = resetToken.createdAt + datetime.timedelta(hours=3)
    print("now: " + str(now) + ", expirationTime: " + str(expirationTime))
    
    if now > expirationTime:
        # delete the token
        resetToken.delete()
        return Response({"error": "Password reset token has expired"}, status=status.HTTP_400_BAD_REQUEST)
  
  except User.DoesNotExist:
    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
  except ResetToken.DoesNotExist:
    return Response({"error": "Invalid reset token"}, status=status.HTTP_400_BAD_REQUEST)
  
  return Response({
        "message": "Token is valid",
        "userID": user.userID
    }, status=status.HTTP_200_OK)
 
@extend_schema(
    summary="Reset Password",
    parameters=[
        OpenApiParameter("email", str, OpenApiParameter.QUERY, description="The user's ID"),
        OpenApiParameter("token", str, OpenApiParameter.QUERY, description="The password reset token"),
    ],
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "userID": {
                    "type": "string",
                    "description": "The user's ID (This should have been saved from the initial request to validate the password reset token/URL)",
                },
                "password": {
                    "type": "string",
                    "description": "The new password for the user",
                },
            },
            "example": {
                "userID": "UBUDF8WEDK23",
                "password": "n3wp@ssworD",
            },
        }
    },
    responses={
        "200": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Success message",
                },
            },
            "example": {
                "message": "Password reset successful",
            },
        },
        "400": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "User's ID is required",
            },
        },
        "404": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "User not found",
            },
        },
        "500": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message",
                },
            },
            "example": {
                "error": "Something went wrong",
            },
        },
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def resetPassword(request):
    """
    Resets the password for a user.
    
    This function is an API view that handles HTTP POST requests to reset a user's password. It expects the request body to contain a JSON object with the following keys:
    
    - `userID`: The ID of the user whose password is being reset.
    - `password`: The new password for the user.
    
    If the password reset is successful, the function returns a Response object with a success message and a 200 status code.
    
    Parameters:
    - `request` (HttpRequest): The HTTP request object containing the request body.
    
    Returns:
    - A Response object with either a success message or an error message, along with the appropriate status code.
    """
    userID = request.data.get("userID")
    password = request.data.get("password")

    if not userID:
        return Response({"error": "User's ID is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    if not password:
        return Response({"error": "User's new password is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(userID=userID)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        # get and delete the password reset token
        resetToken = ResetToken.objects.get(user=user)
        resetToken.delete()

        user.set_password(password)
        user.save()

        # send successful password email to user
        # sendPasswordResetSuccessEmailTask.delay(user.email, user.name)
    except ResetToken.DoesNotExist:
        return Response({"error": "User's password reset token not found"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as exception:
        return Response({"error": "Something went wrong while updating user's password: " + str(exception)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)


@extend_schema(
    responses=UserSerializer
)
class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-dateJoined')
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get All Users",
        parameters=None,
        responses=UserSerializer(many=True),
    )
    def list(self, request):
        """
        Returns all users on the platform
        """
        # return all users
        serializedData = self.serializer_class(self.queryset, many=True)
        return Response(serializedData.data, status=status.HTTP_200_OK)
    
    @extend_schema(
        summary="Create User",
        parameters=[
            OpenApiParameter(name='userID', type=int, location='path', description='ID of the user'),
        ],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the user",
                    },
                },
            }
        },
        responses={
            "405": {
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "description": "response message",
                    }
                },
                "example": {
                    "error": "Creating a user with this endpoint is not allowed"
                }
            }
        },
    )
    def create(self, request):
        """
        Creates a new user.This endpoint is not available though.
        To create a user use the register endpoint
        """
        return Response({'error': 'This endpoint is not available'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    @extend_schema(
        summary="Get User Details",
        parameters=[
            OpenApiParameter(name='userID', type=int, location='path', description='ID of the user'),
        ],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "userID": {
                        "type": "string",
                        "description": "ID of the user",
                    },
                },
            }
        },
        responses={
            "200": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the user",
                    },
                    "email": {
                        "type": "string",
                        "description": "Email of the user",
                    },
                    "phoneNumber": {
                        "type": "string",
                        "description": "Phone number of the user",
                    },
                    "role": {
                        "type": "string",
                        "description": "Role of the user",
                    },
                },
                "example": {
                    "name": "John",
                    "email": "johndoe@x.com",
                    "phoneNumber": "1234567890",
                    "role": "secretary"
                }
            },
            "400": {
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "description": "response message",
                    }
                },
                "example": {
                    "error": "User not found"
                }
            }
        }
    )
    def retrieve(self, request, pk=None):
        """
        Retrieves a user based on the primary key and return serialized data.
        """
        user = get_object_or_404(User, pk=pk)
        serializedData = self.serializer_class(user)
        return Response(serializedData.data, status=status.HTTP_200_OK)
    
    @extend_schema(
        summary="Update User Details",
        parameters=[
            OpenApiParameter(name='name', type=str, location='query', description='Name of the user'),
            OpenApiParameter(name='email', type=str, location='query', description='Email of the user'),
            OpenApiParameter(name='phoneNumber', type=str, location='query', description='Phone number of the user'),
            OpenApiParameter(name='role', type=str, location='query', description='Role of the user'),
        ],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the user",
                    },
                    "email": {
                        "type": "string",
                        "description": "Email of the user",
                    },
                    "phoneNumber": {
                        "type": "string",
                        "description": "Phone number of the user",
                    },
                    "role": {
                        "type": "string",
                        "description": "Role of the user",
                    },
                },
                "required": [
                    "name",
                    "email",
                    "phoneNumber",
                    "role"
                ],
                "example": {
                    "name": "John",
                    "email": "johndoe@x.com",
                    "phoneNumber": "1234567890",
                    "role": "secretary"
                }
            }
        },
        responses={
            "200": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "response message",
                    },
                    "user": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Name of the user",
                            },
                            "email": {
                                "type": "string",
                                "description": "Email of the user",
                            },
                            "phoneNumber": {
                                "type": "string",
                                "description": "Phone number of the user",
                            },
                            "role": {
                                "type": "string",
                                "description": "Role of the user",
                            },
                        },
                    },
                },
                "example": {
                    "message": "User fully updated successfully",
                    "user": {
                        "name": "John",
                        "email": "johndoe@x.com",
                        "phoneNumber": "1234567890",
                        "role": "secretary",
                    }
                }
            },
            "400": {
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "description": "response message",
                    }
                },
                "example": {
                    "error": "User not found"
                }
            }
        }
    )
    def update(self, request, pk=None):
        """
        Fully updates a user's details.
        """
        user = get_object_or_404(User, pk=pk)

        serializer = UserSerializer(user, data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'User fully updated successfully',
                'user': serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Partial Update User Details",
        parameters=[
            OpenApiParameter(name='userID', type=int, location='path', description='ID of the user'),
            OpenApiParameter(name='name', type=str, location='query', description='Name of the user', required=False),
            OpenApiParameter(name='email', type=str, location='query', description='Email of the user', required=False),
            OpenApiParameter(name='phoneNumber', type=str, location='query', description='Phone number of the user', required=False),
            OpenApiParameter(name='role', type=str, location='query', description='Role of the user', required=False),
        ],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the user",
                    },
                    "email": {
                        "type": "string",
                        "description": "Email of the user",
                    },
                    "phoneNumber": {
                        "type": "string",
                        "description": "Phone number of the user",
                    },
                    "role": {
                        "type": "string",
                        "description": "Role of the user",
                    },
                },
                "required": [
                    "name",
                    "email",
                    "phoneNumber",
                    "role"
                ],
                "example": {
                    "name": "John",
                    "email": "johndoe@x.com",
                    "phoneNumber": "1234567890",
                    "role": "secretary"
                }
            },
        },
        responses={
            "200": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "response message",
                    },
                    "user": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Name of the user",
                            },
                            "email": {
                                "type": "string",
                                "description": "Email of the user",
                            },
                            "phoneNumber": {
                                "type": "string",
                                "description": "Phone number of the user",
                            },
                            "role": {
                                "type": "string",
                                "description": "Role of the user",
                            },
                        },
                    },
                },
                "example": {
                    "message": "User partially updated successfully",
                    "user": {
                        "name": "John",
                        "email": "johndoe@x.com",
                        "phoneNumber": "1234567890",
                        "role": "secretary",
                    }
                }
            },
            "400": {
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "description": "response message",
                    }
                },
                "example": {
                    "error": "User not found"
                }
            }
        }
    )
    def partial_update(self, request, pk=None):
        """
        Partially updates a user based on the given primary key.
        """
        user = get_object_or_404(User, pk=pk)

        serializer = UserSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'User partially updated successfully',
                'user': serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Delete User",
        parameters=[
            OpenApiParameter(name='userID', type=int, location='path', description='ID of the user'),
        ],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "userID": {
                        "type": "string",
                        "description": "ID of the user",
                    },
                },
                "required": [
                    "userID"
                ],
                "example": {
                    "userID": "UBUDFD8DFD8"
                }
            },
        },
        responses={
            "204": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "response message",
                    }
                },
                "example": {
                    "message": "User deleted successfully"
                }
            },
            "400": {
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "description": "response message",
                    }
                },
                "example": {
                    "error": "User not found"
                }
            }
        }
    )
    def destroy(self, request, pk, format=None):
        """
        Deletes a user based on the given primary key.
        """
        user = get_object_or_404(User, pk=pk)

        # schedule task to archive user's data
        # archiveUser.delay(user.userID)

        # soft delete the user
        user.isActive = False
        user.save()

        # logout user
        logout(request)

        return Response({'message': 'User deleted and logged out successfully'}, status=status.HTTP_204_NO_CONTENT)
 
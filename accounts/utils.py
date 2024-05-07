import bcrypt
import secrets  # For generating secure random strings
import os
from .models import ResetToken
from accounts.models import User
from rest_framework.response import Response
from rest_framework import status
import datetime
from dateutil import tz
import random

def generateUserID():
    userID = ''

    prefix = 'RAQMS'
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    numbers = '0123456789'

    for i in range(5):
        prefix += letters[random.randint(0, len(letters)-1)]

    for i in range(5):
        prefix += numbers[random.randint(0, len(numbers)-1)]
    
    userID += prefix
    
    return userID

def generateSecureToken():
  """Generates a cryptographically secure random string."""
  return secrets.token_urlsafe(32)

def hashToken(token):
  """Hashes a token using bcrypt."""
  hashToken = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt())
  return hashToken.decode('utf-8')

def saveResetToken(user, token):
  """Saves the hashed reset token and user association to the database."""
  hashedToken = hashToken(token)

  # update or create a new token for the user
  object, created = ResetToken.objects.update_or_create(user=user, defaults={'token': hashedToken})

  return object.token

# def sendWelcomeEmail(email, name):
#   """Sends a welcome email to the user."""

#   subject = "Welcome to UruBytes!"
#   message = f"""
#     <strong>Hi {name},</strong>
#     <p>Thanks for joining UruBytes! We're excited to have you on board.</p>
#     <p>UruBytes is your one-stop shop for empowering organizations to unify their data, analyze it, and thrive on the insights they can glean. Whether you're a beginner or a seasoned pro, you'll find a wealth of resources, features, and opportunities to help you achieve your goals, learn, and connect with others in the data analysis field.</p>
    
#     <strong>Here's what you can do next:</strong>
#     <ul>
#       <li><strong>Explore:</strong> Take a look around and discover the different features we offer. You can [list some key features or actions users can take, e.g., access pre-built data analysis tools, create custom dashboards, collaborate with colleagues].</li>
#       <li><strong>Complete your profile:</strong> Adding a profile picture and some details about yourself can help you connect with other users who share your interests.</li>
#       <li><strong>Join the community:</strong> Engage in discussions, ask questions, and share your knowledge in our forums/groups/[community features].</li>
#     </ul>
    
#     <strong>Here are some helpful links to get you started:</strong>
#     <ul>
#       <li><a href="www.urubytes.com">Help Center</a></li>
#       <li><a href="www.urubytes.com">Groups</a></li>
#     </ul>
    
#     <p>We're always working on improving UruBytes and making it a more valuable resource for our users. If you have any questions or feedback, please don't hesitate to contact us at [Support Email Address].</p>
#     <p>Welcome to the UruBytes community!</p>
    
#     <p>
#       Best regards,
#       <br>
#       The UruBytes Team
#     </p>
#   """

#   sendEmail(email, subject, message)

# def sendPasswordResetRequestEmail(email, token):
#   """Sends a password reset email to the user."""

#   # if we are in production, use the production url, otherwise use the development url
#   if os.getenv("DEVELOPMENT_MODE") == "True":
#     frontendURL = os.getenv("LOCAL_FRONTEND_URL")
#   else:
#     frontendURL = os.getenv("PROD_FRONTEND_URL")

#   passwordResetUrl = f"{frontendURL}/password-reset?email={email}&secret={token}"

#   # construct the email
#   subject = "UruBytes Password Reset"
#   message = f"""
#     Hello,<br><br>

#     You are receiving this email because you requested a password reset for your UruBytes account.<br><br>

#     Click the link below to reset your password:<br><br>

#     {passwordResetUrl}<br><br>

#     <strong>Note: This link will expire in 3 hours for your security.</strong>
    
#     If you didn't request a password reset, you can safely ignore this email.<br><br>

#     If you have any questions, please contact us at <a href="mailto:andrewsankomahene@gmail.com">andrewsankomahene@gmail.com</a>.<br><br>

#     Thanks,<br><br>

#     The UruBytes Team
#   """

#   # send email
#   sendEmail(email, subject, message)

# def sendPasswordResetSuccessEmail(email, name):
#   """Sends a password reset success email to the user."""

#   # if we are in production, use the production url, otherwise use the development url
#   if os.getenv("DEVELOPMENT_MODE") == "True":
#     frontendURL = os.getenv("LOCAL_FRONTEND_URL")
#   else:
#     frontendURL = os.getenv("PROD_FRONTEND_URL")

#   subject = "UruBytes Password Reset Successful"
#   message = f"""
#     <strong>Hi {name},</strong>
#     <p>This email confirms that your password for UruBytes has been successfully reset. You can now log in to your account using your new password.</p>
#     <p>We recommend you keep your password secure and avoid sharing it with anyone.</p>

#     <strong>Here are some helpful links:</strong>
#     <ul>
#       <li><a href="{frontendURL + "/login"}">Login to UruBytes</a></li>
#       <li><a href="{frontendURL + "/help"}">UruBytes Help Center</a></li>
#     </ul>

#     <p>If you did not request a password reset, please contact us immediately at <a href="mailto:andrewsankomahene@gmail.com">andrewsankomahene@gmail.com</a> to secure your account.</p>
    
#     <p>Happy analyzing! </p>
    
#     <p>
#       Best regards,
#       <br>
#       The UruBytes Team
#     </p>
#   """

#   sendEmail(email, subject, message)

# def sendEmail(email, subject, message, name = None):
#   """Sends an email to the user using MailJet"""

#   # set up the MailJet client
#   emailSender = os.getenv('EMAIL_SENDER')
#   emailSenderAddress = os.getenv('EMAIL_SENDER_ADDRESS')
#   apiKey = os.environ['MAILJET_API_KEY']
#   apiSecret = os.environ['MAILJET_SECRET_KEY']
  
#   mailjet = Client(auth=(apiKey, apiSecret), version='v3.1')

#   # send the email
#   result = mailjet.send.create({
#     'Messages': [
#       {
#         "From": {
#           "Email": emailSenderAddress,
#           "Name": emailSender
#         },
#         "To": [
#           {
#             "Email": email,
#             "Name": name
#           }
#         ],
#         "Subject": subject,
#         "HTMLPart": message
#       }
#     ]
#   })

#   if result.status_code == 200:
#     print(subject + " email sent successfully to " + email)
#   else:
#     print("Failed to send " + subject + " email to " + email)
#     print(result.json()) # print the error 
    
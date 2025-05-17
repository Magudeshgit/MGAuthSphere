"""
The Primary purpose of this module is to facillitate security token exchange for ID token with the firebase REST API. 
Since there is no upfront sdk utility available for this specific usecase
"""

import os
import firebase_admin.auth
import requests
import json
from django.conf import settings

GOOGLE_EXCHANGE_URL = "https://securetoken.googleapis.com/v1/token?key="
import firebase_admin
import os


def exchange_token(token):
    k=json.load(open(os.path.join(settings.BASE_DIR,'api/firebase.json')))
    response = requests.post(f"{GOOGLE_EXCHANGE_URL}{k['api_key']}",
                  {
                      "grant_type": "refresh_token",
                      "refresh_token": token
                  })
    if response.status_code == 200:
        print("RECIEVED ID")
        processed = response.json()
        user_profile = firebase_admin.auth.verify_id_token(processed['id_token'], clock_skew_seconds=60)
        [processed.pop(k) for k in ['access_token', 'expires_in', 'token_type', 'user_id', 'project_id', 'refresh_token']]
        processed['user_profile'] = user_profile
        return processed
    else:
        return False

def get_userdetails(id_token):
    k = firebase_admin.auth.verify_id_token(id_token)
    
    
import json
import base64
import hmac
import hashlib
import random
import requests

class MobicardMethod2:
    def __init__(self, merchant_id, api_key, secret_key):
        self.mobicard_version = "2.0"
        self.mobicard_mode = "LIVE"
        self.mobicard_merchant_id = merchant_id
        self.mobicard_api_key = api_key
        self.mobicard_secret_key = secret_key
        self.mobicard_service_id = "20000"
        self.mobicard_service_type = "2"
        self.mobicard_extra_data = "your_custom_data_here_will_be_returned_as_is"
        
        self.mobicard_token_id = str(random.randint(1000000, 1000000000))
        self.mobicard_txn_reference = str(random.randint(1000000, 1000000000))
    
    def image_to_base64(self, image_path=None, image_url=None, base64_string=None):
        """Convert image to base64 string"""
        if base64_string:
            if 'base64,' in base64_string:
                return base64_string.split('base64,')[1]
            return base64_string
        
        if image_url:
            response = requests.get(image_url)
            return base64.b64encode(response.content).decode('utf-8')
        
        if image_path:
            with open(image_path, 'rb') as f:
                return base64.b64encode(f.read()).decode('utf-8')
        
        raise ValueError("No image source provided")
    
    def generate_jwt(self, base64_image):
        """Generate JWT token"""
        jwt_header = {"typ": "JWT", "alg": "HS256"}
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(jwt_header).encode()
        ).decode().rstrip('=')
        
        jwt_payload = {
            "mobicard_version": self.mobicard_version,
            "mobicard_mode": self.mobicard_mode,
            "mobicard_merchant_id": self.mobicard_merchant_id,
            "mobicard_api_key": self.mobicard_api_key,
            "mobicard_service_id": self.mobicard_service_id,
            "mobicard_service_type": self.mobicard_service_type,
            "mobicard_token_id": self.mobicard_token_id,
            "mobicard_txn_reference": self.mobicard_txn_reference,
            "mobicard_scan_card_photo_base64_string": base64_image,
            "mobicard_extra_data": self.mobicard_extra_data
        }
        
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(jwt_payload).encode()
        ).decode().rstrip('=')
        
        header_payload = f"{encoded_header}.{encoded_payload}"
        signature = hmac.new(
            self.mobicard_secret_key.encode(),
            header_payload.encode(),
            hashlib.sha256
        ).digest()
        encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"
    
    def scan_card(self, image_source=None, image_path=None, image_url=None, base64_string=None):
        """Scan card image"""
        try:
            base64_image = self.image_to_base64(
                image_path=image_path,
                image_url=image_url,
                base64_string=base64_string
            )
            
            jwt_token = self.generate_jwt(base64_image)
            
            url = "https://mobicardsystems.com/api/v1/card_scan"
            payload = {"mobicard_auth_jwt": jwt_token}
            
            response = requests.post(url, json=payload, verify=False)
            response_data = response.json()
            
            if response_data.get('status') == 'SUCCESS':
                return self._parse_success_response(response_data)
            else:
                return self._parse_error_response(response_data)
                
        except Exception as e:
            return {'status': 'ERROR', 'error_message': str(e)}
    
    def _parse_success_response(self, response_data):
        """Parse successful response"""
        card_info = response_data.get('card_information', {})
        return {
            'status': 'SUCCESS',
            'card_number': card_info.get('card_number'),
            'card_number_masked': card_info.get('card_number_masked'),
            'card_expiry_date': card_info.get('card_expiry_date'),
            'card_brand': card_info.get('card_brand'),
            'card_bank_name': card_info.get('card_bank_name'),
            'card_confidence_score': card_info.get('card_confidence_score'),
            'validation_checks': card_info.get('card_validation_checks', {}),
            'raw_response': response_data
        }
    
    def _parse_error_response(self, response_data):
        """Parse error response"""
        return {
            'status': 'ERROR',
            'status_code': response_data.get('status_code'),
            'status_message': response_data.get('status_message')
        }

# Usage
scanner = MobicardMethod2(
    merchant_id="4",
    api_key="YmJkOGY0OTZhMTU2ZjVjYTIyYzFhZGQyOWRiMmZjMmE2ZWU3NGIxZWM3ZTBiZSJ9",
    secret_key="NjIwYzEyMDRjNjNjMTdkZTZkMjZhOWNiYjIxNzI2NDQwYzVmNWNiMzRhMzBjYSJ9"
)

# Scan from URL
result = scanner.scan_card(image_url="https://mobicardsystems.com/scan_card_photo_one.jpg")

if result['status'] == 'SUCCESS':
    print(f"Card Number: {result['card_number_masked']}")
    print(f"Expiry Date: {result['card_expiry_date']}")
    print(f"Card Brand: {result['card_brand']}")
    print(f"Bank: {result['card_bank_name']}")
    print(f"Confidence Score: {result['card_confidence_score']}")
    
    if result['validation_checks'].get('luhn_algorithm'):
        print("✓ Luhn Algorithm Check Passed")
    if result['validation_checks'].get('expiry_date'):
        print("✓ Expiry Date is Valid")
    else:
        print("⚠ Expired or Invalid Expiry Date")
else:
    print(f"Error: {result.get('status_message')}")

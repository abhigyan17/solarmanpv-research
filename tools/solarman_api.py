#!/usr/bin/env python3
"""
SolarmanPV Cloud API Client

Communicates with https://homeappapi.solarmanpv.com (and api4pro, smartsetapi)

The SolarmanPV API uses HMAC-SHA256 signing:
  - Sign = HMAC-SHA256(appSecret, sorted_query_params + body)
  - Headers: token: <auth_token>, language: en, sysCode: <appId>, Content-Type: application/json

This client simulates the igen app's signing behavior.
"""

import requests
import json
import time
import hmac
import hashlib
import urllib.parse
from datetime import datetime

# API endpoints discovered
ENDPOINTS = {
    "main":     "https://homeappapi.solarmanpv.com",
    "pro":      "https://api4pro.solarmanpv.com",
    "settings": "https://smartsetapi.solarmanpv.com",
}

# Default headers from app
DEFAULT_HEADERS = {
    "User-Agent": "okhttp/4.10.0",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "language": "en",
    "sysCode": "proapp",
    "Content-Type": "application/json; charset=UTF-8",
}

class SolarmanClient:
    """SolarmanPV API client with HMAC signing"""

    def __init__(self, endpoint: str = "main", app_id: str = "proapp", app_secret: str = ""):
        self.base_url = ENDPOINTS.get(endpoint, endpoint)
        self.app_id = app_id
        self.app_secret = app_secret
        self.token = None
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.session.headers["sysCode"] = app_id

    def _sign(self, method: str, url: str, params: dict, body: str = "") -> str:
        """Compute HMAC-SHA256 signature for the request

        Algorithm (from observed app behavior):
        1. Concatenate method + url + sorted_query_params + body
        2. HMAC-SHA256 with app_secret as key
        3. Base64 encode the result
        """
        # Sort query params
        sorted_params = sorted(params.items())
        param_str = "&".join(f"{k}={v}" for k, v in sorted_params)

        # Build string to sign
        sign_str = f"{method}{url}{param_str}{body}"

        # HMAC-SHA256
        if not self.app_secret:
            return ""  # No signing without secret

        hmac_obj = hmac.new(
            self.app_secret.encode('utf-8'),
            sign_str.encode('utf-8'),
            hashlib.sha256
        )
        return hmac_obj.hexdigest()

    def _make_request(self, method: str, path: str, params: dict = None,
                      body: dict = None) -> dict:
        """Make authenticated API request"""
        url = self.base_url + path
        params = params or {}
        body_str = json.dumps(body) if body else ""

        # Add app_id to params if not present
        if 'appId' not in params:
            params['appId'] = self.app_id

        # Add timestamp
        if 'timestamp' not in params:
            params['timestamp'] = str(int(time.time() * 1000))

        # Add language
        if 'language' not in params:
            params['language'] = 'en'

        # Compute signature
        sign = self._sign(method, path, params, body_str)
        if sign:
            params['sign'] = sign

        # Add token to headers if we have one
        if self.token:
            self.session.headers["token"] = self.token

        # Make request
        print(f"\n[{method}] {url}")
        if params:
            print(f"  Params: {params}")
        if body:
            print(f"  Body: {body_str[:200]}")

        if method == "GET":
            r = self.session.get(url, params=params, timeout=10)
        elif method == "POST":
            r = self.session.post(url, params=params, data=body_str, timeout=10)
        else:
            r = self.session.request(method, url, params=params, data=body_str, timeout=10)

        print(f"  HTTP {r.status_code}")
        print(f"  Response: {r.text[:500]}")

        try:
            return r.json()
        except:
            return {"raw": r.text, "status": r.status_code}

    def login(self, account: str, password: str) -> dict:
        """Login to get auth token"""
        body = {
            "account": account,
            "password": hashlib.md5(password.encode()).hexdigest(),  # MD5!
        }
        result = self._make_request("POST", "/user/login", body=body)
        if isinstance(result, dict) and "data" in result:
            data = result["data"]
            if isinstance(data, dict):
                # Token can be in different fields
                for key in ["token", "access_token", "userToken"]:
                    if key in data:
                        self.token = data[key]
                        print(f"\n[+] Got token: {self.token[:30]}...")
                        break
        return result

    def get_devices(self) -> dict:
        """List all devices for the logged-in user"""
        return self._make_request("POST", "/device/list", body={"page": 1, "size": 20})

    def get_device_realtime(self, device_id: str) -> dict:
        """Get real-time data for a device"""
        return self._make_request("POST", f"/device/{device_id}/realtime", body={})

    def get_stations(self) -> dict:
        """List all stations"""
        return self._make_request("POST", "/station/list", body={"page": 1, "size": 20})

    def sdk_check(self) -> dict:
        """SDK version check (public endpoint)"""
        return self._make_request("POST", "/deviceConfig-s/sdk/check", body={})


def demo():
    """Demo the SolarmanPV API"""
    print("=" * 70)
    print("SOLARMANPV API CLIENT DEMO")
    print("=" * 70)

    # Use main endpoint
    client = SolarmanClient("main")

    # Test 1: SDK check (no auth required)
    print("\n--- Test 1: SDK Check (public) ---")
    result = client.sdk_check()
    print(f"  Result: {result}")

    # Test 2: Login (requires credentials)
    # NOTE: This won't work without valid credentials
    print("\n--- Test 2: Login (would require valid creds) ---")
    print("  Skipping - requires valid SolarmanPV account credentials")

    # Test 3: Try to access a protected endpoint without auth
    print("\n--- Test 3: Try devices without auth ---")
    result = client.get_devices()
    print(f"  Result: {result}")


if __name__ == "__main__":
    demo()

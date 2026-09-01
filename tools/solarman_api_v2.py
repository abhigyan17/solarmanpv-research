#!/usr/bin/env python3
"""
SolarmanPV Web API Client - COMPLETE
Uses the CORRECT OAuth endpoint discovered from app reverse engineering.

Source: com.oemfuture.solar.BuildConfig.URLBASE = "https://api4pro.solarmanpv.com"
        com.igen.regerakit.service.ApiService.login()
        OAuth endpoint: https://homeappapi.solarmanpv.com/oauth2-s/oauth/token

Usage:
  python solarman_api_v2.py login <email> <password>     # Get access token
  python solarman_api_v2.py devices                       # List your inverters
  python solarman_api_v2.py stations                      # List your plants
  python solarman_api_v2.py realtime <device_id>         # Get real-time data
  python solarman_api_v2.py history <device_id> <YYYY-MM-DD>
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import sys
import os
import argparse
from datetime import datetime

# ============================================================================
# API Configuration (from reverse engineering)
# ============================================================================
API_BASE = "https://homeappapi.solarmanpv.com"  # OAuth endpoint host
APP_BASE = "https://api4pro.solarmanpv.com"    # Invergy app's URLBASE
CLIENT_ID = "proapp"  # sysCode / client_id
TOKEN_FILE = "solarman_token.json"


# ============================================================================
# OAuth Authentication (from ApiService.java)
# ============================================================================
def login(email, password, identity_type="1", client_id=CLIENT_ID):
    """
    Authenticate with SolarmanPV and get OAuth access token.

    identity_type: "1" = email, "2" = phone (with country code prefix)

    Endpoint: POST https://homeappapi.solarmanpv.com/oauth2-s/oauth/token
    Body (form-urlencoded):
      grant_type=password
      identity_type=1|2
      username=<email_or_phone>
      password=<password>
      clear_text_pwd=<password>
      client_id=proapp
    """
    url = f"{API_BASE}/oauth2-s/oauth/token"

    data = urllib.parse.urlencode({
        "grant_type": "password",
        "identity_type": identity_type,
        "username": email,
        "password": password,
        "clear_text_pwd": password,
        "client_id": client_id,
    }).encode()

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "okhttp/4.10.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "language": "en",
        "sysCode": client_id,
    }

    req = urllib.request.Request(url, data=data, method='POST', headers=headers)

    try:
        response = urllib.request.urlopen(req, timeout=15)
        result = json.loads(response.read().decode())

        # Save for reuse
        token_data = {
            'access_token': result.get('access_token'),
            'refresh_token': result.get('refresh_token'),
            'token_type': result.get('token_type', 'bearer'),
            'expires_in': result.get('expires_in', 7199),
            'scope': result.get('scope', 'server'),
            'email': email,
            'obtained_at': datetime.now().isoformat(),
        }

        with open(TOKEN_FILE, 'w') as f:
            json.dump(token_data, f, indent=2)

        print(f"[+] Login successful!")
        print(f"    Email:      {email}")
        print(f"    Token:      {token_data['access_token'][:50]}...")
        print(f"    Expires in: {token_data['expires_in']}s")
        print(f"    Saved to:   {TOKEN_FILE}")
        return token_data

    except urllib.error.HTTPError as e:
        try:
            error_body = json.loads(e.read().decode())
        except:
            error_body = e.read().decode()

        print(f"[-] Login failed: HTTP {e.code}")
        print(f"    {error_body}")

        if e.code == 401:
            print(f"\n    Possible causes:")
            print(f"    1. Wrong email/password")
            print(f"    2. Account not registered on SolarmanPV")
            print(f"    3. Need to use phone login (identity_type=2)")
        return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def load_token():
    """Load saved token from file"""
    if not os.path.exists(TOKEN_FILE):
        print(f"[-] No token found. Please login first:")
        print(f"    python {sys.argv[0]} login <email> <password>")
        sys.exit(1)

    with open(TOKEN_FILE) as f:
        return json.load(f)


def refresh_token(token_data):
    """Refresh expired access token"""
    url = f"{API_BASE}/oauth2-s/oauth/token"
    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": token_data['refresh_token'],
        "client_id": CLIENT_ID,
    }).encode()

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "okhttp/4.10.0",
        "language": "en",
        "sysCode": CLIENT_ID,
    }

    try:
        req = urllib.request.Request(url, data=data, method='POST', headers=headers)
        response = urllib.request.urlopen(req, timeout=15)
        result = json.loads(response.read().decode())

        token_data.update({
            'access_token': result.get('access_token'),
            'refresh_token': result.get('refresh_token', token_data['refresh_token']),
            'expires_in': result.get('expires_in', 7199),
            'obtained_at': datetime.now().isoformat(),
        })

        with open(TOKEN_FILE, 'w') as f:
            json.dump(token_data, f, indent=2)

        print(f"[+] Token refreshed")
        return token_data
    except Exception as e:
        print(f"[-] Token refresh failed: {e}")
        return None


# ============================================================================
# API Request Helper
# ============================================================================
def api_request(path, method='GET', body=None, token_data=None):
    """Make authenticated API request to homeappapi.solarmanpv.com"""
    if token_data is None:
        token_data = load_token()

    url = f"{API_BASE}{path}"
    headers = {
        "Authorization": f"Bearer {token_data['access_token']}",
        "User-Agent": "okhttp/4.10.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "language": "en",
        "sysCode": CLIENT_ID,
        "Content-Type": "application/json; charset=UTF-8",
    }

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)

    try:
        response = urllib.request.urlopen(req, timeout=15)
        return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except:
            body = e.read().decode()

        if e.code == 401:
            print("[-] Token expired, attempting refresh...")
            token_data = refresh_token(token_data)
            if token_data:
                # Retry with new token
                headers["Authorization"] = f"Bearer {token_data['access_token']}"
                req = urllib.request.Request(url, data=data, method=method, headers=headers)
                try:
                    response = urllib.request.urlopen(req, timeout=15)
                    return json.loads(response.read().decode())
                except:
                    pass

        return {"error": body, "status": e.code}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# High-level API methods
# ============================================================================
def list_devices():
    """List all inverters/datloggers for the authenticated user"""
    result = api_request("/device-s/device/product-device-list",
                         method='POST', body={"page": 1, "size": 100})
    return result


def list_stations():
    """List all plants/stations"""
    result = api_request("/station/list", method='POST',
                         body={"page": 1, "size": 100})
    return result


def get_realtime(device_id):
    """Get real-time data for a specific device"""
    result = api_request("/device-s/diy/currentData/getById",
                         method='POST', body={"deviceId": device_id, "type": "1"})
    return result


def get_history(device_id, date_str):
    """Get historical data for a device"""
    result = api_request("/station/realTime", method='POST',
                         body={"deviceId": device_id, "date": date_str})
    return result


def get_alarms(device_id=None, station_id=None):
    """Get alarms for a device or station"""
    if device_id:
        return api_request(f"/station/alarm", method='POST',
                          body={"deviceId": device_id})
    return None


# ============================================================================
# CLI
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="SolarmanPV Web API Client")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # login
    p_login = subparsers.add_parser('login', help='Authenticate and get token')
    p_login.add_argument('email', help='Email or phone (with country code)')
    p_login.add_argument('password', help='Password')
    p_login.add_argument('--phone', action='store_true',
                          help='Treat username as phone number (identity_type=2)')

    # devices
    subparsers.add_parser('devices', help='List your inverters')

    # stations
    subparsers.add_parser('stations', help='List your stations/plants')

    # realtime
    p_rt = subparsers.add_parser('realtime', help='Get real-time data')
    p_rt.add_argument('device_id', help='Device ID (from devices list)')

    # history
    p_hist = subparsers.add_parser('history', help='Get historical data')
    p_hist.add_argument('device_id', help='Device ID')
    p_hist.add_argument('date', help='Date YYYY-MM-DD')

    # alarms
    p_alarm = subparsers.add_parser('alarms', help='Get alarms')
    p_alarm.add_argument('device_id', help='Device ID')

    args = parser.parse_args()

    if args.command == 'login':
        identity_type = "2" if args.phone else "1"
        login(args.email, args.password, identity_type=identity_type)

    elif args.command == 'devices':
        token = load_token()
        result = list_devices()
        print(json.dumps(result, indent=2))

    elif args.command == 'stations':
        result = list_stations()
        print(json.dumps(result, indent=2))

    elif args.command == 'realtime':
        result = get_realtime(args.device_id)
        print(json.dumps(result, indent=2))

    elif args.command == 'history':
        result = get_history(args.device_id, args.date)
        print(json.dumps(result, indent=2))

    elif args.command == 'alarms':
        result = get_alarms(args.device_id)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
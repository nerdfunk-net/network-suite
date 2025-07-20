"""nerdfunk network suite - Flask web application for IP address validation.

This module provides a simple web interface for validating IP addresses
against Nautobot DCIM endpoint with user authentication.
"""

from __future__ import annotations

import logging
from pathlib import Path
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from pynautobot import api
import requests
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "your-secret-key-change-this"  # Change this in production

# Configuration
USERNAMES_FILE = Path("usernames.txt")
PASSWORDS_FILE = Path("passwords.txt")
CONFIG_FILE = Path("config.json")


def load_config() -> dict:
    """Load configuration from config.json file.
    
    Returns:
        Dictionary containing configuration settings.
        
    Raises:
        FileNotFoundError: If config file doesn't exist.
        json.JSONDecodeError: If config file has invalid JSON.
    """
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            config = json.load(f)
        logger.info("Configuration loaded successfully")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {CONFIG_FILE} not found")
        raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found. Please create it with Nautobot settings.")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        raise json.JSONDecodeError(f"Invalid JSON in configuration file: {e}")
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise


# Load configuration
config = load_config()

# Nautobot Configuration from config file
NAUTOBOT_URL = config['nautobot']['url']
NAUTOBOT_USERNAME = config['nautobot']['username']
NAUTOBOT_API_TOKEN = config['nautobot']['api_token']

# Server Configuration from config file
SERVER_HOST = config.get('server', {}).get('host', '127.0.0.1')
SERVER_PORT = config.get('server', {}).get('port', 5003)
SERVER_DEBUG = config.get('server', {}).get('debug', True)


def load_users() -> dict[str, str]:
    """Load usernames and passwords from files.
    
    Returns:
        Dictionary mapping usernames to passwords.
        
    Raises:
        FileNotFoundError: If username or password files don't exist.
        ValueError: If files have mismatched number of entries.
    """
    try:
        with USERNAMES_FILE.open("r", encoding="utf-8") as f:
            usernames = [line.strip() for line in f if line.strip()]
        
        with PASSWORDS_FILE.open("r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        if len(usernames) != len(passwords):
            raise ValueError("Usernames and passwords files have mismatched entries")
        
        return dict(zip(usernames, passwords))
    except FileNotFoundError as e:
        logger.error(f"Authentication files not found: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading users: {e}")
        raise


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate a user against the stored credentials.
    
    Args:
        username: The username to authenticate.
        password: The password to check.
        
    Returns:
        True if authentication successful, False otherwise.
    """
    try:
        users = load_users()
        return username in users and users[username] == password
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return False


def login_required(f):
    """Decorator to require login for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_nautobot_connection():
    """Get connection to Nautobot API.
    
    Returns:
        Nautobot API connection object.
        
    Raises:
        Exception: If unable to connect to Nautobot.
    """
    try:
        nautobot = api(
            url=NAUTOBOT_URL,
            token=NAUTOBOT_API_TOKEN,
        )
        return nautobot
    except Exception as e:
        logger.error(f"Failed to connect to Nautobot: {e}")
        raise


def check_ip_address_in_nautobot(ip_address: str) -> dict[str, any]:
    """Check if IP address exists in Nautobot using GraphQL query.
    
    Args:
        ip_address: The IP address to check.
        
    Returns:
        Dictionary with 'exists' boolean and 'device' data if found.
        
    Raises:
        Exception: If unable to query Nautobot.
    """
    try:
        # Prepare GraphQL query
        query = """
        query device (
          $ip_address: [String]
        ) {
          ip_addresses(address: $ip_address) {
            primary_ip4_for {
              name
            }
          }
        }
        """
        
        # Prepare variables
        variables = {
            "ip_address": [ip_address]
        }
        
        # Prepare the payload
        payload = {
            "query": query,
            "variables": variables
        }
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Make the GraphQL request
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        # Check if there are any errors in the GraphQL response
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        # Parse the response
        data = result.get('data', {})
        ip_addresses = data.get('ip_addresses', [])

        if ip_addresses and len(ip_addresses) > 0:
            # IP address found
            ip_obj = ip_addresses[0]
            primary_ip4_for = ip_obj.get('primary_ip4_for')

            if primary_ip4_for:
                device_name = primary_ip4_for[0].get('name', 'Unknown')
                logger.info(f"IP address {ip_address} found in Nautobot, assigned to device: {device_name}")
                
                return {
                    'exists': True,
                    'device': {
                        'name': device_name,
                        'ip_address': ip_address
                    }
                }
            else:
                # IP exists but not assigned to any device
                logger.info(f"IP address {ip_address} found in Nautobot but not assigned to any device")
                return {
                    'exists': True,
                    'device': None
                }
        else:
            # IP address not found
            logger.info(f"IP address {ip_address} not found in Nautobot")
            return {'exists': False, 'device': None}
            
    except Exception as e:
        logger.error(f"Error checking IP address {ip_address} in Nautobot via GraphQL: {e}")
        raise


def get_nautobot_locations() -> list[dict[str, any]]:
    """Get list of all locations from Nautobot using GraphQL query.
    
    Returns:
        List of location dictionaries with 'id' and 'name' keys.
        
    Raises:
        Exception: If unable to query Nautobot locations.
    """
    try:
        # Prepare GraphQL query for locations
        query = """
        query locations {
          locations {
            id
            name
          }
        }
        """
        
        # Prepare the payload
        payload = {
            "query": query
        }
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Make the GraphQL request
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        # Check if there are any errors in the GraphQL response
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        # Parse the response
        data = result.get('data', {})
        locations = data.get('locations', [])
        
        logger.info(f"Retrieved {len(locations)} locations from Nautobot")
        return locations
            
    except Exception as e:
        logger.error(f"Error fetching locations from Nautobot via GraphQL: {e}")
        raise


def get_nautobot_namespaces() -> list[dict[str, any]]:
    """Get list of all namespaces from Nautobot using GraphQL query."""
    try:
        query = """
        query namespace {
          namespaces {
            id
            name
          }
        }
        """
        
        payload = {"query": query}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        data = result.get('data', {})
        namespaces = data.get('namespaces', [])
        
        logger.info(f"Retrieved {len(namespaces)} namespaces from Nautobot")
        return namespaces
            
    except Exception as e:
        logger.error(f"Error fetching namespaces from Nautobot via GraphQL: {e}")
        raise


def get_nautobot_roles() -> list[dict[str, any]]:
    """Get list of all roles from Nautobot using GraphQL query."""
    try:
        query = """
        query roles {
          roles {
            id
            name
          }
        }
        """
        
        payload = {"query": query}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        data = result.get('data', {})
        roles = data.get('roles', [])
        
        logger.info(f"Retrieved {len(roles)} roles from Nautobot")
        return roles
            
    except Exception as e:
        logger.error(f"Error fetching roles from Nautobot via GraphQL: {e}")
        raise


def get_nautobot_platforms() -> list[dict[str, any]]:
    """Get list of all platforms from Nautobot using GraphQL query."""
    try:
        query = """
        query platforms {
          platforms {
            id
            name
          }
        }
        """
        
        payload = {"query": query}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        data = result.get('data', {})
        platforms = data.get('platforms', [])
        
        logger.info(f"Retrieved {len(platforms)} platforms from Nautobot")
        return platforms
            
    except Exception as e:
        logger.error(f"Error fetching platforms from Nautobot via GraphQL: {e}")
        raise


def get_nautobot_statuses() -> list[dict[str, any]]:
    """Get list of all statuses from Nautobot using GraphQL query."""
    try:
        query = """
        query status {
          statuses {
            id
            name
          }
        }
        """
        
        payload = {"query": query}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        data = result.get('data', {})
        statuses = data.get('statuses', [])
        
        logger.info(f"Retrieved {len(statuses)} statuses from Nautobot")
        return statuses
            
    except Exception as e:
        logger.error(f"Error fetching statuses from Nautobot via GraphQL: {e}")
        raise


def get_nautobot_secrets_groups() -> list[dict[str, any]]:
    """Get list of all secrets groups from Nautobot using GraphQL query."""
    try:
        query = """
        query secrets_groups {
          secrets_groups {
            id
            name
          }
        }
        """
        
        payload = {"query": query}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        data = result.get('data', {})
        secrets_groups = data.get('secrets_groups', [])
        
        logger.info(f"Retrieved {len(secrets_groups)} secrets groups from Nautobot")
        return secrets_groups
            
    except Exception as e:
        logger.error(f"Error fetching secrets groups from Nautobot via GraphQL: {e}")
        raise


def search_devices_by_location(location_pattern: str) -> list[dict[str, any]]:
    """Search for devices by location using regex pattern via GraphQL query.
    
    Args:
        location_pattern: Regular expression pattern to match location names.
        
    Returns:
        List of device dictionaries with name, id, role, location, primary_ip4, and status.
        
    Raises:
        Exception: If unable to query Nautobot devices.
    """
    try:
        # Prepare GraphQL query for location-based device search
        query = """
        query devives_in_location (
            $location_filter: [String]
        ) {
            locations (name__re: $location_filter) {
                name
                devices {
                    id
                    name
                    role {
                        name
                    }
                    location {
                        name
                    }
                    primary_ip4 {
                        address
                    }
                    status {
                        name
                    }
                }
            }
        }
        """
        
        # Prepare variables
        variables = {
            "location_filter": [location_pattern]
        }
        
        # Prepare the payload
        payload = {
            "query": query,
            "variables": variables
        }
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Make the GraphQL request
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        # Check if there are any errors in the GraphQL response
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        # Parse the response and flatten the nested device structure
        data = result.get('data', {})
        locations = data.get('locations', [])
        
        # Flatten devices from all matching locations
        all_devices = []
        for location in locations:
            devices = location.get('devices', [])
            all_devices.extend(devices)
        
        logger.info(f"Retrieved {len(all_devices)} devices from locations matching pattern '{location_pattern}'")
        return all_devices
            
    except Exception as e:
        logger.error(f"Error searching devices by location pattern '{location_pattern}' via GraphQL: {e}")
        raise


def search_devices_by_tag(tag_pattern: str) -> list[dict[str, any]]:
    """Search for devices by tag using pattern via GraphQL query.
    
    Args:
        tag_pattern: Tag name pattern to match devices.
        
    Returns:
        List of device dictionaries with name, id, role, location, primary_ip4, and status.
        
    Raises:
        Exception: If unable to query Nautobot devices.
    """
    try:
        # Prepare GraphQL query for tag-based device search
        query = """
        query devices_by_tags($tag_filter: [String]) {
            devices(tags: $tag_filter) {
                name
                id
                role {
                    name
                }
                location {
                    name
                }
                primary_ip4 {
                    address
                }
                status {
                    name
                }
            }
        }
        """
        
        # Prepare variables
        variables = {
            "tag_filter": [tag_pattern]
        }
        
        # Prepare the payload
        payload = {
            "query": query,
            "variables": variables
        }
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Make the GraphQL request
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        # Check if there are any errors in the GraphQL response
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        # Parse the response
        data = result.get('data', {})
        devices = data.get('devices', [])
        
        logger.info(f"Retrieved {len(devices)} devices with tag '{tag_pattern}'")
        return devices
            
    except Exception as e:
        logger.error(f"Error searching devices by tag '{tag_pattern}' via GraphQL: {e}")
        raise


def search_devices_by_regex(regex_pattern: str) -> list[dict[str, any]]:
    """Search for devices in Nautobot using regex pattern via GraphQL query.
    
    Args:
        regex_pattern: Regular expression pattern to match device names.
        
    Returns:
        List of device dictionaries with name, id, role, location, primary_ip4, and status.
        
    Raises:
        Exception: If unable to query Nautobot devices.
    """
    try:
        # Prepare GraphQL query for device search (updated to include id)
        query = """
        query devices (
            $regular_expression: [String]
        ) {
            devices (name__re: $regular_expression) {
                name
                id
                role {
                  name
                }
                location {
                  name
                }
                primary_ip4 {
                  address
                }
                status {
                  name
                }
            }
        }
        """
        
        # Prepare variables
        variables = {
            "regular_expression": [regex_pattern]
        }
        
        # Prepare the payload
        payload = {
            "query": query,
            "variables": variables
        }
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Make the GraphQL request
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        # Check if there are any errors in the GraphQL response
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        # Parse the response
        data = result.get('data', {})
        devices = data.get('devices', [])
        
        logger.info(f"Retrieved {len(devices)} devices matching pattern '{regex_pattern}'")
        return devices
            
    except Exception as e:
        logger.error(f"Error searching devices with pattern '{regex_pattern}' via GraphQL: {e}")
        raise


def get_device_id_by_name(device_name: str) -> str | None:
    """Get device UUID by device name using GraphQL query.
    
    Args:
        device_name: The name of the device to find.
        
    Returns:
        Device UUID string if found, None otherwise.
        
    Raises:
        Exception: If unable to query Nautobot devices.
    """
    try:
        # Prepare GraphQL query for device search
        query = """
        query device (
            $device_name: [String]
        ) {
            devices (name: $device_name) {
                id
                name
            }
        }
        """
        
        # Prepare variables
        variables = {
            "device_name": [device_name]
        }
        
        # Prepare the payload
        payload = {
            "query": query,
            "variables": variables
        }
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Make the GraphQL request
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            logger.error(f"GraphQL query failed: {response.status_code} - {response.text}")
            raise Exception(f"GraphQL query failed with status {response.status_code}")
        
        result = response.json()
        
        # Check if there are any errors in the GraphQL response
        if 'errors' in result:
            logger.error(f"GraphQL errors: {result['errors']}")
            raise Exception(f"GraphQL query errors: {result['errors']}")
        
        # Parse the response
        data = result.get('data', {})
        devices = data.get('devices', [])
        
        if devices and len(devices) > 0:
            device_id = devices[0].get('id')
            logger.info(f"Found device {device_name} with ID: {device_id}")
            return device_id
        else:
            logger.warning(f"Device {device_name} not found in Nautobot")
            return None
            
    except Exception as e:
        logger.error(f"Error finding device ID for {device_name} via GraphQL: {e}")
        raise


def sync_device_network_data(device_id: str, device_name: str, status_id: str, namespace_id: str, sync_cables: bool = True, sync_software_version: bool = True, sync_vlans: bool = True, sync_vrfs: bool = True) -> dict[str, any]:
    """Sync network data for a specific device using the Sync Network Data From Network job.
    
    Args:
        device_id: The UUID of the device to sync.
        device_name: The name of the device (for logging).
        status_id: The ID of the status for network objects.
        namespace_id: The ID of the namespace.
        sync_cables: Whether to sync cables (default: True).
        sync_software_version: Whether to sync software version (default: True).
        sync_vlans: Whether to sync VLANs (default: True).
        sync_vrfs: Whether to sync VRFs (default: True).
        
    Returns:
        Dictionary with 'success' boolean and 'message' or 'error' details.
    """
    try:
        url = f"{NAUTOBOT_URL}/api/extras/jobs/Sync%20Network%20Data%20From%20Network/run/"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        data = {
            "data": {
                "devices": [device_id],  # Use device UUID in a list
                "default_prefix_status": status_id,
                "interface_status": status_id,
                "ip_address_status": status_id,
                "namespace": namespace_id,
                "sync_cables": sync_cables,
                "sync_software_version": sync_software_version,
                "sync_vlans": sync_vlans,
                "sync_vrfs": sync_vrfs
            }
        }
        
        logger.info(f"Syncing network data for device: {device_name} (ID: {device_id})")
        logger.info(f"Sync parameters - Device: {device_name}, Device ID: {device_id}, Status ID: {status_id}, Namespace ID: {namespace_id}")
        
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code in [200, 201, 202]:
            logger.info(f"Successfully initiated network data sync for device {device_name}")
            return {
                'success': True,
                'message': f'Network data sync job started for device {device_name}',
                'job_id': response.json().get('job_result', {}).get('id', 'Unknown') if response.json() else 'Unknown'
            }
        else:
            logger.error(f"Failed to sync network data for device {device_name}: {response.status_code} - {response.text}")
            return {
                'success': False,
                'error': f'HTTP {response.status_code}: {response.text}'
            }
            
    except Exception as e:
        logger.error(f"Error syncing network data for device {device_name}: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def add_device_to_nautobot(ip_address: str, location_id: str, secret_groups_id: str, role_id: str, namespace_id: str, status_id: str, platform_id: str) -> dict[str, any]:
    """Add a device to Nautobot using the Sync Devices From Network job.
    
    Args:
        ip_address: The IP address of the device.
        location_id: The ID of the location where the device is installed.
        secret_groups_id: The ID of the secrets group for the device.
        role_id: The ID of the device role.
        namespace_id: The ID of the namespace.
        status_id: The ID of the device status.
        platform_id: The ID of the platform.
        
    Returns:
        Dictionary with 'success' boolean and 'message' or 'error' details.
        
    Raises:
        Exception: If unable to add device to Nautobot.
    """
    try:
        url = f"{NAUTOBOT_URL}/api/extras/jobs/Sync%20Devices%20From%20Network/run/"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        data = {
            "data": {
                "location": location_id,
                "ip_addresses": ip_address,
                "secrets_group": secret_groups_id,
                "device_role": role_id,
                "namespace": namespace_id,
                "device_status": status_id,
                "interface_status": status_id,
                "ip_address_status": status_id,
                "platform": platform_id,
                "port": 22,
                "timeout": 30,
                "update_devices_without_primary_ip": False
            }
        }
        
        logger.info(f"Adding device to Nautobot: IP={ip_address}, Location_ID={location_id}, Role_ID={role_id}")
        
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code in [200, 201, 202]:
            logger.info(f"Successfully initiated device sync for IP {ip_address}")
            return {
                'success': True,
                'message': f'Device sync job started successfully for IP {ip_address}',
                'job_id': response.json().get('job_result', {}).get('id', 'Unknown') if response.json() else 'Unknown'
            }
        else:
            logger.error(f"Failed to add device to Nautobot: {response.status_code} - {response.text}")
            return {
                'success': False,
                'error': f'HTTP {response.status_code}: {response.text}'
            }
            
    except Exception as e:
        logger.error(f"Error adding device {ip_address} to Nautobot: {e}")
        raise


def validate_ip_address(ip_address: str) -> bool:
    """Validate IP address format.
    
    Args:
        ip_address: The IP address to validate.
        
    Returns:
        True if valid, False otherwise.
    """
    import ipaddress
    
    if not ip_address or not ip_address.strip():
        return False
    
    try:
        # This will validate both IPv4 and IPv6 addresses
        ipaddress.ip_address(ip_address.strip())
        return True
    except ValueError:
        return False


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handle user login."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Please enter both username and password.", "error")
            return redirect(url_for("login"))
        
        if authenticate_user(username, password):
            session['username'] = username
            logger.info(f"User {username} logged in successfully")
            return redirect(url_for("index"))
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Handle user logout."""
    username = session.get('username', 'Unknown')
    session.pop('username', None)
    logger.info(f"User {username} logged out")
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Handle the main page with IP address validation form."""
    if request.method == "POST":
        ip_address = request.form.get("ip_address", "").strip()
        
        if not ip_address:
            flash("Please enter an IP address.", "error")
            return redirect(url_for("index"))
        
        if not validate_ip_address(ip_address):
            flash("Invalid IP address format.", "error")
            return redirect(url_for("index"))
        
        try:
            result = check_ip_address_in_nautobot(ip_address)
            
            if result['exists']:
                device = result['device']
                if device:
                    flash(f"✅ IP address '{ip_address}' found in Nautobot and assigned to device: {device['name']}", "success")
                else:
                    flash(f"✅ IP address '{ip_address}' found in Nautobot but not assigned to any device.", "warning")
            else:
                # Store IP address in session for the onboarding form
                session['onboard_ip'] = ip_address
                return redirect(url_for("onboard_device"))
                
        except Exception as e:
            logger.error(f"Error checking IP address: {e}")
            flash(f"Error checking IP address: {str(e)}", "error")
        
        return redirect(url_for("index"))
    
    return render_template("index.html")


@app.route("/onboard", methods=["GET", "POST"])
@login_required
def onboard_device():
    """Handle device onboarding form when IP is not found in Nautobot."""
    ip_address = session.get('onboard_ip')
    if not ip_address:
        flash("No IP address to onboard. Please check an IP address first.", "error")
        return redirect(url_for("index"))
    
    if request.method == "POST":
        # Get form data (all IDs now)
        location = request.form.get("location", "").strip()
        secret_groups = request.form.get("secret_groups", "").strip()
        role = request.form.get("role", "").strip()
        namespace = request.form.get("namespace", "").strip()
        status = request.form.get("status", "").strip()
        platform = request.form.get("platform", "").strip()
        
        # Validate required fields
        required_fields = {
            'location': location,
            'secret_groups': secret_groups,
            'role': role,
            'namespace': namespace,
            'status': status,
            'platform': platform
        }
        
        missing_fields = [field for field, value in required_fields.items() if not value]
        if missing_fields:
            flash(f"Please fill in all required fields: {', '.join(missing_fields)}", "error")
            return redirect(url_for("onboard_device"))
        
        try:
            result = add_device_to_nautobot(
                ip_address=ip_address,
                location_id=location,
                secret_groups_id=secret_groups,
                role_id=role,
                namespace_id=namespace,
                status_id=status,
                platform_id=platform
            )
            
            if result['success']:
                flash(f"✅ Device onboarding initiated successfully!", "success")
                flash(f"Job ID: {result['job_id']} - {result['message']}", "info")
                # Clear the IP from session
                session.pop('onboard_ip', None)
                return redirect(url_for("index"))
            else:
                flash(f"❌ Failed to onboard device: {result['error']}", "error")
                return redirect(url_for("onboard_device"))
                
        except Exception as e:
            logger.error(f"Error during device onboarding: {e}")
            flash(f"Error during device onboarding: {str(e)}", "error")
            return redirect(url_for("onboard_device"))
    
    # Fetch all data for dropdowns
    try:
        locations = get_nautobot_locations()
        namespaces = get_nautobot_namespaces()
        roles = get_nautobot_roles()
        platforms = get_nautobot_platforms()
        statuses = get_nautobot_statuses()
        secrets_groups = get_nautobot_secrets_groups()
    except Exception as e:
        logger.error(f"Error fetching data from Nautobot: {e}")
        flash(f"Error fetching data from Nautobot: {str(e)}", "error")
        locations = []
        namespaces = []
        roles = []
        platforms = []
        statuses = []
        secrets_groups = []
    
    return render_template("onboard_device.html", 
                         ip_address=ip_address, 
                         locations=locations,
                         namespaces=namespaces,
                         roles=roles,
                         platforms=platforms,
                         statuses=statuses,
                         secrets_groups=secrets_groups)


@app.route("/sync-device")
@login_required
def sync_device():
    """Render the sync device page with device search and sync functionality.
    
    Returns:
        Rendered sync device template.
    """
    return render_template("sync_device.html")


@app.route("/api/search-devices", methods=["POST"])
@login_required
def api_search_devices():
    """API endpoint to search for devices using regex pattern."""
    try:
        data = request.get_json()
        if not data or 'pattern' not in data:
            return {"error": "Missing pattern parameter"}, 400
        
        pattern = data['pattern'].strip()
        if len(pattern) < 3:
            return {"error": "Pattern must be at least 3 characters"}, 400
        
        # Get search type (default to 'name')
        search_type = data.get('search_type', 'name')
        
        if search_type == 'location':
            devices = search_devices_by_location(pattern)
        elif search_type == 'tag':
            devices = search_devices_by_tag(pattern)
        else:  # default to name search
            devices = search_devices_by_regex(pattern)
            
        return {"devices": devices}, 200
        
    except Exception as e:
        logger.error(f"Error in device search API: {e}")
        return {"error": str(e)}, 500


@app.route('/api/sync-devices', methods=['POST'])
@login_required
def api_sync_devices():
    """API endpoint to sync selected devices"""
    try:
        data = request.get_json()
        devices = data.get('devices', [])  # Now expects list of device objects with id and name
        status_id = data.get('status_id')
        namespace_id = data.get('namespace_id')
        sync_cables = data.get('sync_cables', True)  # Default: True
        sync_software_version = data.get('sync_software_version', True)  # Default: True
        sync_vlans = data.get('sync_vlans', True)  # Default: True
        sync_vrfs = data.get('sync_vrfs', True)  # Default: True
        
        if not devices:
            return jsonify({'error': 'No devices provided'}), 400
            
        if not status_id or not namespace_id:
            return jsonify({'error': 'Status and namespace are required'}), 400
        
        results = []
        successful = 0
        failed = 0
        
        for device in devices:
            device_id = device.get('id')
            device_name = device.get('name', 'Unknown')
            
            if not device_id:
                results.append({
                    'device': device_name,
                    'status': 'error',
                    'message': f'Missing device ID for {device_name}'
                })
                failed += 1
                continue
                
            try:
                result = sync_device_network_data(device_id, device_name, status_id, namespace_id, sync_cables, sync_software_version, sync_vlans, sync_vrfs)
                if result and result.get('success', False):
                    results.append({
                        'device': device_name,
                        'status': 'success',
                        'message': result.get('message', f'Sync initiated for {device_name}')
                    })
                    successful += 1
                else:
                    results.append({
                        'device': device_name,
                        'status': 'failed',
                        'message': result.get('error', f'Failed to sync {device_name}') if result else f'Failed to sync {device_name}'
                    })
                    failed += 1
            except Exception as e:
                results.append({
                    'device': device_name,
                    'status': 'error',
                    'message': f'Error syncing {device_name}: {str(e)}'
                })
                failed += 1
        
        return jsonify({
            'success': True,
            'summary': {
                'total': len(devices),
                'successful': successful,
                'failed': failed
            },
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': f'Sync operation failed: {str(e)}'}), 500

@app.route('/api/dropdown-data', methods=['GET'])
@login_required
def api_dropdown_data():
    """API endpoint to get dropdown data for sync configuration"""
    try:
        # Get statuses and namespaces
        statuses = get_nautobot_statuses()
        namespaces = get_nautobot_namespaces()
        
        return jsonify({
            'success': True,
            'statuses': statuses,
            'namespaces': namespaces
        })
    
    except Exception as e:
        return jsonify({'error': f'Failed to load dropdown data: {str(e)}'}), 500


if __name__ == "__main__":
    app.run(debug=SERVER_DEBUG, host=SERVER_HOST, port=SERVER_PORT)

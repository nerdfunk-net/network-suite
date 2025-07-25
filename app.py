"""nerdfunk network suite - Flask web application for IP address validation.

This module provides a simple web interface for validating IP addresses
against Nautobot DCIM endpoint with user authentication.
"""

from __future__ import annotations

import json
import logging
import os
import ipaddress
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
    """Load configuration from config.json file with environment variable overrides.
    
    Environment variables take precedence over config.json values:
    - NAUTOBOT_URL: Nautobot server URL
    - NAUTOBOT_USERNAME: Nautobot username  
    - NAUTOBOT_API_TOKEN: Nautobot API token
    - SERVER_HOST: Flask server host
    - SERVER_PORT: Flask server port
    - SERVER_DEBUG: Flask debug mode (true/false)
    
    Returns:
        Dictionary containing configuration settings.
        
    Raises:
        FileNotFoundError: If config file doesn't exist and required env vars are missing.
        json.JSONDecodeError: If config file has invalid JSON.
    """
    # Default configuration
    config = {
        "nautobot": {
            "url": "http://localhost:8080",
            "username": "admin", 
            "api_token": ""
        },
        "server": {
            "host": "127.0.0.1",
            "port": 5003,
            "debug": True
        }
    }
    
    # Load from config.json if it exists
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("r", encoding="utf-8") as f:
                file_config = json.load(f)
                # Merge file config with defaults
                for section, values in file_config.items():
                    if section in config:
                        config[section].update(values)
                    else:
                        config[section] = values
            logger.info("Configuration loaded from config.json")
        else:
            logger.warning(f"Configuration file {CONFIG_FILE} not found, using defaults")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        raise json.JSONDecodeError(f"Invalid JSON in configuration file: {e}")
    except Exception as e:
        logger.error(f"Error loading configuration file: {e}")
    
    # Override with environment variables
    if os.getenv('NAUTOBOT_URL'):
        config['nautobot']['url'] = os.getenv('NAUTOBOT_URL')
        logger.info("NAUTOBOT_URL overridden from environment variable")
        
    if os.getenv('NAUTOBOT_USERNAME'):
        config['nautobot']['username'] = os.getenv('NAUTOBOT_USERNAME')
        logger.info("NAUTOBOT_USERNAME overridden from environment variable")
        
    if os.getenv('NAUTOBOT_API_TOKEN'):
        config['nautobot']['api_token'] = os.getenv('NAUTOBOT_API_TOKEN')
        logger.info("NAUTOBOT_API_TOKEN overridden from environment variable")
        
    if os.getenv('SERVER_HOST'):
        config['server']['host'] = os.getenv('SERVER_HOST')
        logger.info("SERVER_HOST overridden from environment variable")
        
    if os.getenv('SERVER_PORT'):
        try:
            config['server']['port'] = int(os.getenv('SERVER_PORT'))
            logger.info("SERVER_PORT overridden from environment variable")
        except ValueError:
            logger.error("Invalid SERVER_PORT environment variable, using default")
            
    if os.getenv('SERVER_DEBUG'):
        debug_val = os.getenv('SERVER_DEBUG').lower()
        config['server']['debug'] = debug_val in ('true', '1', 'yes', 'on')
        logger.info("SERVER_DEBUG overridden from environment variable")
    
    # Validate required configuration
    if not config['nautobot']['api_token']:
        logger.error("NAUTOBOT_API_TOKEN is required but not set")
        raise ValueError("NAUTOBOT_API_TOKEN is required. Set it in config.json or as environment variable.")
    
    return config


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


def search_devices_by_prefix(prefix_pattern: str) -> list[dict[str, any]]:
    """Search for devices by IP prefix using GraphQL query.
    
    Args:
        prefix_pattern: IP prefix to match devices (e.g., '192.168.1.0/24').
        
    Returns:
        List of device dictionaries with name, id, role, location, primary_ip4, and status.
        
    Raises:
        Exception: If unable to query Nautobot devices.
    """
    try:
        # Prepare GraphQL query for prefix-based device search
        query = """
        query devices_by_ip_prefix($prefix_filter: [String]) {
            prefixes(within_include: $prefix_filter) {
                prefix
                ip_addresses {
                    primary_ip4_for {
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
            }
        }
        """
        
        # Prepare variables
        variables = {
            "prefix_filter": [prefix_pattern]
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
        prefixes = data.get('prefixes', [])
        
        # Flatten devices from all matching prefixes
        all_devices = []
        for prefix in prefixes:
            ip_addresses = prefix.get('ip_addresses', [])
            for ip_addr in ip_addresses:
                primary_ip4_for = ip_addr.get('primary_ip4_for')
                if primary_ip4_for:
                    # primary_ip4_for is a list, so we need to iterate through it
                    if isinstance(primary_ip4_for, list):
                        all_devices.extend(primary_ip4_for)
                    else:
                        all_devices.append(primary_ip4_for)
        
        logger.info(f"Retrieved {len(all_devices)} devices from prefix '{prefix_pattern}'")
        return all_devices
            
    except Exception as e:
        logger.error(f"Error searching devices by prefix '{prefix_pattern}' via GraphQL: {e}")
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
            job_result = response.json().get('job_result', {}) if response.json() else {}
            job_id = job_result.get('id', 'Unknown')
            logger.info(f"Successfully initiated network data sync for device {device_name}")
            return {
                'success': True,
                'message': f'Network data sync job started for device {device_name}',
                'job_id': job_id,
                'job_url': f"{NAUTOBOT_URL}/extras/job-results/{job_id}/" if job_id != 'Unknown' else None
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


@app.route("/", methods=["GET"])
@login_required
def index():
    """Handle the dashboard page."""
    return render_template("dashboard.html")


@app.route("/onboard", methods=["GET", "POST"])
@login_required
def onboard_device():
    """Handle device onboarding - IP validation and device setup."""
    # Check if we're coming from an IP check or if IP is already in session
    ip_address = session.get('onboard_ip')
    
    if request.method == "POST":
        # Check if this is an IP validation request
        if 'ip_address' in request.form:
            ip_address = request.form.get("ip_address", "").strip()
            
            if not ip_address:
                flash("Please enter an IP address.", "error")
                return redirect(url_for("onboard_device"))
            
            if not validate_ip_address(ip_address):
                flash("Invalid IP address format.", "error")
                return redirect(url_for("onboard_device"))
            
            try:
                result = check_ip_address_in_nautobot(ip_address)
                
                if result['exists']:
                    device = result['device']
                    if device:
                        flash(f"✅ IP address '{ip_address}' found in Nautobot and assigned to device: {device['name']}", "success")
                        return redirect(url_for("onboard_device"))
                    else:
                        flash(f"✅ IP address '{ip_address}' found in Nautobot but not assigned to any device.", "warning")
                        return redirect(url_for("onboard_device"))
                else:
                    # Store IP address in session for the onboarding form
                    session['onboard_ip'] = ip_address
                    flash(f"IP address '{ip_address}' not found in Nautobot. Please configure the device details below.", "info")
                    return redirect(url_for("onboard_device"))
                    
            except Exception as e:
                logger.error(f"Error checking IP address: {e}")
                flash(f"Error checking IP address: {str(e)}", "error")
                return redirect(url_for("onboard_device"))
        
        # Handle device onboarding form submission
        else:
            ip_address = session.get('onboard_ip')
            if not ip_address:
                flash("No IP address to onboard. Please check an IP address first.", "error")
                return redirect(url_for("onboard_device"))
            
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
                    return redirect(url_for("onboard_device"))
                else:
                    flash(f"❌ Failed to onboard device: {result['error']}", "error")
                    return redirect(url_for("onboard_device"))
                    
            except Exception as e:
                logger.error(f"Error during device onboarding: {e}")
                flash(f"Error during device onboarding: {str(e)}", "error")
                return redirect(url_for("onboard_device"))
    
    # GET request - show the onboarding page
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
        elif search_type == 'prefix':
            devices = search_devices_by_prefix(pattern)
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
                        'message': result.get('message', f'Sync initiated for {device_name}'),
                        'job_id': result.get('job_id'),
                        'job_url': result.get('job_url')
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


@app.route('/api/job-status/<job_id>', methods=['GET'])
@login_required
def api_job_status(job_id):
    """API endpoint to check job status"""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Get job details
        url = f"{NAUTOBOT_URL}/api/extras/job-results/{job_id}/"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return jsonify({'error': f'Failed to get job status: {response.status_code}'}), 500
        
        job_data = response.json()
        
        # Extract relevant information
        status = job_data.get('status', {}).get('name', 'unknown')
        date_created = job_data.get('date_created')
        date_done = job_data.get('date_done')
        result = job_data.get('result', {})
        
        # Calculate progress based on status
        progress = 0
        if status.lower() == 'pending':
            progress = 10
        elif status.lower() in ['running', 'started']:
            progress = 50
        elif status.lower() in ['completed', 'success']:
            progress = 100
        elif status.lower() in ['failed', 'errored']:
            progress = 100
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'status': status,
            'progress': progress,
            'date_created': date_created,
            'date_done': date_done,
            'result': result,
            'is_finished': status.lower() in ['completed', 'success', 'failed', 'errored']
        })
    
    except Exception as e:
        logger.error(f"Error checking job status {job_id}: {e}")
        return jsonify({'error': f'Failed to check job status: {str(e)}'}), 500


@app.route('/api/active-jobs', methods=['GET'])
@login_required
def api_active_jobs():
    """API endpoint to get active jobs count"""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Get recent job results (last 100, filter for running/pending)
        url = f"{NAUTOBOT_URL}/api/extras/job-results/"
        params = {
            'limit': 100,
            'status': 'pending,running,started'
        }
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code != 200:
            return jsonify({'active_jobs': 0})
        
        job_data = response.json()
        active_count = job_data.get('count', 0)
        
        return jsonify({
            'success': True,
            'active_jobs': active_count
        })
    
    except Exception as e:
        logger.error(f"Error getting active jobs: {e}")
        return jsonify({'active_jobs': 0})


@app.route('/api/device-count', methods=['GET'])
@login_required
def api_device_count():
    """API endpoint to get total device count from Nautobot"""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Get device count using the specific endpoint from nautobot_access.md
        url = f"{NAUTOBOT_URL}/api/dcim/devices/"
        params = {
            'depth': 0,
            'limit': 1,
            'offset': 1
        }
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code != 200:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch device count: {response.status_code}'
            }), 500
        
        data = response.json()
        device_count = data.get('count', 0)
        
        logger.info(f"Retrieved device count: {device_count}")
        return jsonify({
            'success': True,
            'count': device_count
        })
    
    except Exception as e:
        logger.error(f"Error getting device count: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/recent-changes', methods=['GET'])
@login_required
def api_recent_changes():
    """API endpoint to get last 10 changes from Nautobot"""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Get recent changes using the specific endpoint from nautobot_access.md
        url = f"{NAUTOBOT_URL}/api/extras/object-changes/"
        params = {
            'limit': 10,
            'offset': 0
        }
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code != 200:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch recent changes: {response.status_code}'
            }), 500
        
        data = response.json()
        changes = data.get('results', [])
        
        logger.info(f"Retrieved {len(changes)} recent changes")
        return jsonify({
            'success': True,
            'changes': changes
        })
    
    except Exception as e:
        logger.error(f"Error getting recent changes: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/system-status', methods=['GET'])
@login_required
def api_system_status():
    """API endpoint to get Nautobot system status"""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # Get system status using the endpoint from nautobot_access.md
        url = f"{NAUTOBOT_URL}/api/status/"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch system status: {response.status_code}',
                'nautobot_version': 'Connection Error',
                'nautobot_apps_version': 'Connection Error'
            }), 200  # Return 200 so frontend can still show partial status
        
        data = response.json()
        
        # Extract relevant status information
        nautobot_version = data.get('nautobot-version', 'Unknown')
        django_version = data.get('django-version', 'Unknown')
        python_version = data.get('python-version', 'Unknown')
        
        # Extract nautobot-apps from the specific "nautobot-apps" parameter
        nautobot_apps_dict = data.get('nautobot-apps', {})
        nautobot_apps_info = []
        
        # Process the nautobot-apps dictionary
        if nautobot_apps_dict and isinstance(nautobot_apps_dict, dict):
            for app_name, app_version in nautobot_apps_dict.items():
                nautobot_apps_info.append(f"{app_name}: {app_version}")
        
        # Format the apps information
        if nautobot_apps_info:
            nautobot_apps_version = ", ".join(nautobot_apps_info)
            # If too long, truncate and show count
            if len(nautobot_apps_version) > 100:
                nautobot_apps_version = f"{len(nautobot_apps_info)} apps: " + ", ".join(nautobot_apps_info[:2]) + "..."
        else:
            nautobot_apps_version = 'No apps installed'
        
        logger.info(f"Retrieved system status - Nautobot: {nautobot_version}, Apps: {nautobot_apps_version}")
        return jsonify({
            'success': True,
            'nautobot_version': nautobot_version,
            'nautobot_apps_version': nautobot_apps_version,
            'django_version': django_version,
            'python_version': python_version,
            'nautobot_apps_dict': nautobot_apps_dict,  # Include raw dict for frontend if needed
            'raw_data': data  # Include full response for debugging
        })
    
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'nautobot_version': 'Connection Error',
            'nautobot_apps_version': 'Connection Error'
        }), 200  # Return 200 so frontend can still show partial status


@app.route('/api/outdated-backups', methods=['GET'])
@login_required
def api_outdated_backups():
    """API endpoint to get devices with outdated backups"""
    try:
        # Get date filter from query parameter, default to current date
        from datetime import datetime
        current_date = datetime.now().strftime('%Y-%m-%d')
        date_filter = request.args.get('date', current_date)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {NAUTOBOT_API_TOKEN}"
        }
        
        # GraphQL query for devices with outdated backups
        query = """
        query backup_device($date_filter: [String]) {
            devices(cf_last_backup__lt: $date_filter) {
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
                cf_last_backup
            }
        }
        """
        
        # Prepare GraphQL request
        graphql_data = {
            "query": query,
            "variables": {
                "date_filter": [date_filter]
            }
        }
        
        # Make GraphQL request
        url = f"{NAUTOBOT_URL}/api/graphql/"
        response = requests.post(url, headers=headers, json=graphql_data)
        
        if response.status_code != 200:
            logger.error(f"GraphQL request failed with status {response.status_code}: {response.text}")
            return jsonify({
                'success': False,
                'error': f'GraphQL request failed: {response.status_code}',
                'devices': []
            }), 500
        
        data = response.json()
        
        # Check for GraphQL errors
        if 'errors' in data:
            logger.error(f"GraphQL errors: {data['errors']}")
            return jsonify({
                'success': False,
                'error': f'GraphQL errors: {data["errors"]}',
                'devices': []
            }), 500
        
        devices = data.get('data', {}).get('devices', [])
        
        logger.info(f"Retrieved {len(devices)} devices with outdated backups (before {date_filter})")
        return jsonify({
            'success': True,
            'devices': devices,
            'date_filter': date_filter,
            'count': len(devices)
        })
    
    except Exception as e:
        logger.error(f"Error getting outdated backup devices: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'devices': []
        }), 500


if __name__ == "__main__":
    app.run(debug=SERVER_DEBUG, host=SERVER_HOST, port=SERVER_PORT)

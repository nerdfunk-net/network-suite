# nerdfunk network suite

## Features

- **User Authentication**: Login system with username/password files
- **Nautobot Integration**: Check if IP addresses exist in Nautobot IPAM
- **Device Onboarding**: Automatically onboard new devices when IP not found
- Input validation for IP address format (IPv4 and IPv6)
- Flash messages for user feedback with detailed device information
- Session management with logout functionality

This application is a web application written in Python using Flask as the application framework.

## Features

- **User Authentication**: Login system with username/password files
- **Nautobot Integration**: Check if IP addresses exist in Nautobot DCIM
- Input validation for IP address format (IPv4 and IPv6)
- View devices from Nautobot DCIM endpoint with IP address information
- Flash messages for user feedback with detailed device information
- Session management with logout functionality

## Nautobot Integration

The application connects to Nautobot using GraphQL queries to validate IP addresses. It uses a REST API call with GraphQL query payload as specified in the nautobot_access.md file.

### Nautobot Configuration

Configuration is now stored in `config.json`. Copy `config.example.json` to `config.json` and update with your settings:

```json
{
  "nautobot": {
    "url": "http://your-nautobot-server:8080",
    "username": "your-admin-username",
    "api_token": "your-api-token-here"
  },
  "server": {
    "host": "127.0.0.1",
    "port": 5003,
    "debug": true
  }
}
```

**Configuration Details:**
- **Nautobot URL**: Your Nautobot server URL (e.g., http://localhost:8080)
- **Username**: Admin username for Nautobot
- **API Token**: Generated API token from Nautobot (32+ character hex string)
- **Server Host**: IP address to bind the Flask server to (default: 127.0.0.1)
- **Server Port**: TCP port for the Flask server (default: 5003)
- **Debug Mode**: Enable Flask debug mode (default: true for development)
- **Endpoint**: GraphQL API (`/api/graphql/`)
- **Query**: Uses GraphQL to find IP addresses and their device assignments

### Nautobot Configuration:
- **URL**: http://localhost:8080
- **Username**: admin
- **API Token**: 0123456789abcdef0123456789abcdef01234567
- **Endpoint**: DCIM devices

## Authentication

The application uses file-based authentication:
- Usernames are stored in `usernames.txt` (one per line)
- Passwords are stored in `passwords.txt` (one per line, corresponding to usernames)

### Default Demo Credentials:
- `admin` / `admin123`
- `user` / `password`  
- `guest` / `guest123`

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. **Configure Nautobot Connection**:
   Copy the example configuration file and update with your Nautobot settings:
   ```bash
   cp config.example.json config.json
   ```
   
   Edit `config.json` with your Nautobot server details:
   ```json
   {
     "nautobot": {
       "url": "http://your-nautobot-server:8080",
       "username": "your-admin-username", 
       "api_token": "your-api-token-here"
     },
     "server": {
       "host": "127.0.0.1",
       "port": 5003,
       "debug": true
     }
   }
   ```

## Running the Application

```bash
python app.py
```

The application will be available at `http://127.0.0.1:5003` (or the host:port configured in your `config.json`)

## Usage

1. Open your browser and navigate to the application URL
2. **Log in** with valid credentials (see demo credentials above)
3. Enter an IP address in the form field (supports both IPv4 and IPv6)
4. Click "Onboard device" button
5. The application will query Nautobot using GraphQL and:
   - ✅ **Found & Assigned**: Display IP address with assigned device name
   - ✅ **Found & Unassigned**: Show IP exists but no device assignment
   - ❌ **Not Found**: Redirect to device onboarding form
6. **If IP not found**, fill out the onboarding form with:
   - Location (physical location)
   - Namespace (network namespace)
   - Device Role (Router, Switch, Server, etc.)
   - Platform (Cisco-IOS, Ubuntu, Windows, etc.)
   - Status (Active, Planned, Staged, etc.)
   - Secrets Group (credential group name)
7. Submit the form to initiate device sync job in Nautobot
8. Click "Logout" when finished

## Project Structure

```
.
├── app.py                        # Main Flask application with Nautobot integration
├── config.json                   # Nautobot configuration (create from config.example.json)
├── config.example.json          # Example configuration file
├── templates/
│   ├── base.html                # Base template with navigation
│   ├── login.html               # Login page
│   ├── index.html               # Main IP address check page (protected)
│   ├── onboard_device.html      # Device onboarding form (protected)
│   └── sync_device.html         # Sync device page (protected)
├── .github/docs/
│   └── nautobot_access.md       # Nautobot connection configuration
├── usernames.txt                # User credentials (usernames)
├── passwords.txt                # User credentials (passwords)
├── requirements.txt             # Python dependencies (Flask + pynautobot)
└── README.md                    # This file
```

## Dependencies

- **Flask**: Web framework
- **pynautobot**: Nautobot API client library
- **requests**: HTTP library for API calls

## Security Notes

- Change the Flask secret key in production
- Consider using password hashing (bcrypt) for production use  
- File-based authentication is suitable for demo/development purposes
- For production, consider using a proper database and authentication system
- **Keep `config.json` secure** - contains sensitive API tokens
- **Never commit `config.json`** to version control - use `config.example.json` instead
- Nautobot API token should be secured and rotated regularly

This application is a web application written in Python. 
The application uses flask as application framework.
The start page consists of a form. The form consists of an input field “Hostname” and a submit button
If the user has entered a host name and pressed the Submit button, the application should write the name to a file. The file can be found in the local directory and is called hosts.txt

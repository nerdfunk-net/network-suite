# Basics to access nautboot

## To access nautobot use the library pynautobot.

## Here are the data to access nautobot:

* nautobot_hostname: http://localhost:8080
* nautobot_username: admin
* nautobot_api_token: 0123456789abcdef0123456789abcdef01234567
* To check if a hostname is in nautobot use the dcim endpoint.

# To check if an IP address is already in nautobot use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * It is possible to provide a list of variables in the same payload as presented below.
  * Use this query:

    query device (
      $ip_address: [String]
    ) {
      ip_addresses(address: $ip_address) {
        primary_ip4_for {
          name
        }
      }
    }

# To get a list of all locations in nautobot use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * Use this query:

    query locations {
      locations {
        id
        name
      }
    }

# To get a list of all namespaces in nautobot use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * Use this query:

    query namespace {
      namespaces {
        id
        name
      }
    }

# To get a list of all roles in nautobot use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * Use this query:

    query roles {
      roles {
        id
        name
      }
    }

# To get a list of all roles in nautobot use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * Use this query:

    query roles {
      roles {
        id
        name
      }
    }

# To get a list of all roles in platforms use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * Use this query:

    query platforms {
      platforms {
        id
        name
      }
    }

# To get a list of all roles in statuses use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * Use this query:

    query status {
      statuses {
        id
        name
      }
    }

# To get a list of all roles in secrets groups use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * Use this query:

    query secrets_groups {
      secrets_groups {
        id
        name
      }
    }

# To get the most important data of a single device use a graphql query and make a REST API call. 
  * A GraphQL Query must be encapsulated in a JSON payload with the query key and sent with a POST request. 
  * The parameter device_filter is used to get the data of a device.
  * Use you can name__re instead of name to use a regular expression. In this case you ghet a list of devices that matches the regular expression.
  * The result will contain the name of a device, the role, the location and the primary_ipv4 address.
  * Use this query:

    query single_device (
    $device_filter: [String]) 
    {
      devices (name:$device_filter) {
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

# To Sync a device to nautobot use the following properties:

 * use POST as method
 * use the URL "{{ nautobot_hostname }}/api/extras/jobs/Sync%20Devices%20From%20Network/run/"
 * the header must contain
  -  Content-Type: application/json
  - Authorization: "Token nautobot_api_token"
 * add "body_format: json" to the request
 * ask the user to enter the following data:
    1. ip_address
    2. location
    3. secret_groups
    4. role
    5. namespace
    6. status
    7. platform
 * the body must contain a dict called 'data' that contains the following properties:

      "location": location,
      'ip_addresses': ip_address,
      "secrets_group": secret_groups,
      "device_role": role,
      "namespace": namespace,
      "device_status": status,
      "interface_status": status,
      "ip_address_status": status,
      "platform": platform,
      "port": 22,
      "timeout": 30,
      "update_devices_without_primary_ip": false

# To sync the device with the network data use the following properties:

 * use POST as method
 * use the URL "{{ nautobot_hostname }}/api/extras/jobs/Sync%20Network%20Data%20From%20Network/run/"
 * the header must contain
  -  Content-Type: application/json
  - Authorization: "Token nautobot_api_token"
 * add "body_format: json" to the request
 * ask the user to enter the following data:
    1. status (selection)
    2. namespace (selection)
    3. Sync Cables (parameter is named sync_cables) as checkbox
    4. Sync Software (parameter is sync_software_version) as checkbox
    5. Sync VLANs (parameter is named sync_vlans) as checkbox
    6. Sync VRFs (parameter is named sync_vrfs) as checkbox
 * the body must contain a dict called 'data' that contains the following properties:

        "devices": device_name,
        "default_prefix_status": status,
        "interface_status": status,
        "ip_address_status": status,
        "namespace": namespace,
        "sync_cables": sync_cables,
        "sync_software_version": sync_software_version,
        "sync_vlans": sync_vlans,
        "sync_vrfs": sync_vrfs
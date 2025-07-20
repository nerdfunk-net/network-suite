# Sync Device App

  * The app contains a table. This table is empty at the beginning. The table contains the following columns:
    1. checkbox named 'sync'. This checkbox not selected at the beginning.
    2. Device Name
    3. Primary IP
    4. Location
    5. Role
    6. Status 

  * At the bottom you can see a Submit Button called 'Sync Devices'
  * At the top of the table is a text input field. You can use this text input as filter. The filter works as follows: 
    1. After the user has entered at least three characters the app is looking in nautobot to get a list of devices that matches the filter. The search should be triggered on every keystroke after 3 characters. Use a delay of 20ms. 
    2. When no devices are found do nothing. When a network error occurs notify the user with a message. When the regular expression is invalid notify the user. 
    3. A regular expression query is used. Use this query to get a list of devices:

        query devices (
            $regular_expression: [String])
            {
            devices (name__re:$regular_expression) {
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

    4. Before the new list os added to the table, all rows where the checkbox is not selected are removed.
    5. The result of this query contains a list of devices. These devices are added to the table. 
  * After the sync button is clicked do the following:
    1. For each selected device (checkbox is selected) in the table use this POST request. Use the request that is described in nautobot_access.md under the section 'Sync a device to nautobot use the following properties:'
      
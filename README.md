# warframe-irc-server

An IRC server that space ninjas can connect to.

## Building

- Use [Sun](https://github.com/calamity-inc/Sun)
- Make sure [Soup](https://github.com/calamity-inc/Soup) is cloned under the same parent directory

## Server Config

The login response of the WF HTTP server needs to contain `"IRC": ["localhost:6699"]`.

For SpaceNinjaServer, this can be achieved by adding `"myIrcAddresses": ["localhost:6699"]` to the config.json.

If your server is hosted remotely, replace `localhost` appropriately.

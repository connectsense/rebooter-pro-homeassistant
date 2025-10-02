# rebooter-pro-homeassistant

## Development

**While developing, take these steps to load the custom integration on your Home Assistant hub:**
* Add the "File editor" add-on to your Home Assistant hub. In Home Assistant: Settings → Add-ons → Add-on Store → search File editor
* Click File editor in the sidebar. Use the folder icon to browse the file system.
* The base directory the "File editor" will be the "/config" directory on the hub, but will show up as "homeassistant/".
* If there is not yet a folder named "custom_components" create one.
* Within "custom_components" creare a folder named "rebooter_pro"
* In "rebooter_pro" coppy all contents of this repository EXCEPT this README.md file. This includes all subdirectories, which you will have to create manually
* Restart the Home Assistant hub File editor → Settings Gear on Top Right → Restart Home Assistant

**To enable logging in Home Assistant for the Rebooter Pro integration, do the following:**
* Click File editor in the sidebar. Use the folder icon to browse the file system.
* Under the base directory edit the "configuration.yaml" file
* Add the following:

```
logger:
default: info
logs:
    zeroconf: info
    homeassistant.components.zeroconf: debug
    custom_components.rebooter_pro: debug
```

* Click the save button

## Testing
**As soon a Rebooter Pro is added to your network it should appear as follows** 
* In your overview page as a device named Rebooter Pro 10XXXXX. There will be a reboot button and an outlet toggle button in it's device box.
* Under Settings → Devices & Services → Devices, as a device named Rebooter Pro 10XXXXX
* Under Settings → Devices & Services → Integrations → Rebooter Pro, it wil show up as an Integration entry named Rebooter Pro 10XXXXX
 
**You can manually set up a Rebooter Pro (should automatically work) by doing the following**
* Under Settings → Devices & Services → Integrations, click "Add integration".
* Search for and select Rebooter Pro.
* It will ask you for the Host or mDNS name. The default (rebooter-pro.local)is true if you only have 1 rebooter on your network. Alternatively you can enter an IP address.
* It will ask you for the Port. This is always 443 (wont work otherwise) and will be removed as a config option in the future.
* Keep Verify SSL certificate checked, as the certificate is embedded. I wall also be removing this config option in the future.
* Click Submit. It will add the Rebooter Pro for you (whether it is there and responsive or not).

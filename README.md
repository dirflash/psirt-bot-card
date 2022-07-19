![PSIRT Bot](https://user-images.githubusercontent.com/10964629/172955101-76942969-039e-402a-a1c0-e3ed6c71ab38.png)

# Python PSIRT Bot

---

**In beta!**

### Documentation is hard

**Still working on the documentation. It's not complete, or accurate, at the moment!**

---

# Getting Started

1.  [Problem Statement](#what-problem-is-this-script-trying-to-solve)
2.  [Requirements](#requirements-for-running-in-autonomous-bot-mode)
3.  [Webex](#webex)
4.  [Webex Webhook](#webex-webhook)
5.  [Send a Webex test message](#webex-test-message)
6.  [Pipedream Setup](#pipedream)
7.  [Cisco API Console Registration](#cisco-api-console-registration)
8.  [PSQRT Walk Through](#usage-walk-through)
9.  [Workflow Diagram](#bot-workflow)
10. [References](#references)

## What problem is this script trying to solve?

Using the [Cisco Security Advisories portal](https://tools.cisco.com/security/center/publicationListing.x), it can be difficult to determine what PSIRT notifications have been updated with new information, affected products, workarounds, and patches.

This project creates a Webex App bot, using buttons and cards, that utilizes Webex Webhooks, [Pipedream workflows](https://pipedream.com), the [Cisco PSIRT openVuln API](https://developer.cisco.com/docs/psirt/?utm_source=devblog&utm_medium=christophervandermade&utm_campaign=securex-page&utm_term=fy22-q2-0000&utm_content=log4j2andpsirt01-ww), MongoDB, and Github Actions to respond to a Webex App message, and deliver an XLXS file of all updated Cisco PSIRT notifications that have occurred in the last 7 days.

This XLXS file will make it easier for a security team to review updated PSIRT information and take any required remediation without the need of setting up a Python environment and creating all the required connections.

## Requirements for running in autonomous Bot mode

Registered accounts with the following services:

1.  Webex - https://web.webex.com
    You can use the browser based client without installing the Webex messaging application. But the Webex app makes things easier.
2.  Pipedream - https://pipedream.com
3.  Cisco PSIRT OpenVuln API - https://developer.cisco.com/psirt/
4.  MongoDB - https://www.mongodb.com
5.  Github - https://github.com

Running separately, and concurrently, is [psirt-gsheets](https://github.com/dirflash/psirt-gsheets). This script creates a Google Sheets document with the updated Cisco PSIRTs. The PSIRT Bot uses the Google Sheets publish to the web functionality to attach the latest report to the Webex app response.

### Webex

1.  Create an account at https://www.webex.com.
2.  Create a [new Bot app](https://developer.webex.com/my-apps/new).
    - Record the following details:
    - Bot access token
    - Bot username
    - Bot ID

### Webex Webhook

Using the Webex for Developers documentation, create a "messages" -> "created" and "attachmentActions" -> "created" Webhook.
The target URL in the Webhook configuration is the [Pipedream Webhook receiver URL](#w_r_URL).

![Sample Webhook](https://user-images.githubusercontent.com/10964629/179615236-5dc6b4bd-4116-420e-8b53-a6444ad2c397.png)

## Webex Test Message

From the Webex app, send a test message to the newly created Webex Bot. This message should appear in the "Select Event" section of the HTTP?Webhook "Trigger" event in Pipedream.

![Test Message](https://user-images.githubusercontent.com/10964629/179617300-46af75dc-e36f-4552-b7b5-6468918e9b9e.png)

### Pipedream

1. Create a Pipedream.com account
2. Click on "Settings"
3. Click on "Environment Variables"
4. Click on "NEW ENVIRONMENT VARIABLE"
5. Create the following Environment Variables
   - "Bearer" - Webex App Bearer Token
   - "git_action" - Github Action Token
   - "psirt_otoken_client_id" - Obtained in the ["Cisco API Console Registration"](https://github.com/dirflash/psirt-bot#cisco-api-console-registration) section
   - "psirt_otoken_client_secret" - Obtained in the ["Cisco API Console Registration"](https://github.com/dirflash/psirt-bot#cisco-api-console-registration) section

![enviro_vars](https://user-images.githubusercontent.com/10964629/178057241-fbd9a22a-e0aa-4abd-99d8-4710e8b4fd53.JPG)

6. Create a new Workflow
7. Add a trigger
   - Select "HTTP/Webhook"
   - Select "HTTP Requests"
   - Click "Save and Continue"
     <a name="w_r_URL"></a>
   - Safely record and store the Webhook receiver URL

![trigger_1](https://user-images.githubusercontent.com/10964629/178046780-1e054c26-3769-48ab-bed9-430a1fbc9308.jpg)

8. Click on the plus sign underneath the trigger step
9. Add a Python step
10. Select "Run Python Code"
11. Name the step "get_user"
12. Add the code included in the following image

![trigger_2](https://user-images.githubusercontent.com/10964629/178047393-451db592-30ed-410a-86e5-7a36e56a2b0a.JPG)

13. Click on the plus sign underneath the "get_user" step
14. In the "Search for an app" field, type "filter"
15. Select "Filter"
16. Select "End Workflow on Custom Condition"
17. Click on the "Reason" box and expand the "steps" data
18. Select "First_Name"
19. Complete the "Reason" logic to look like the following image

![trigger_3](https://user-images.githubusercontent.com/10964629/178048441-3c0edc97-e0f2-4019-889c-a4ae7719839b.JPG)
**Note: To be able to find the required fields, a test messages must have been sent to the Pipedream receiver by following the instructions in the "Webex" section above.**

20. Follow the same steps to complete the "Condition" logic
21. Click on the plus sign underneath the trigger step
22. Add a Python step
23. Select "Run Python Code"
24. Name the step "get_msg"
25. Add the code included in the following image

![trigger_4](https://user-images.githubusercontent.com/10964629/178049252-84ece278-32ab-4acf-895b-5ec8f09037f6.JPG)

26. Go back to the main Pipedream dashboard and select "Accounts"
27. Click "CONNECT AN APP"
28. In the "Search for an App" box, type "Mongo"
29. Select "MongoDB"
30. Complete the required account information and validate Pipedream can connect to your MongoDB database
31. Click on the plus sign underneath the "get_msg" step
32. In the "Search for an app" field, type "mongo"
33. Select "MongoDB"
34. Select "Use any MongoDB API"
35. Complete the "MongoDB Account", "Database", "Collection" fields to connect MongoDB
36. Add the "Data" objects and expressions to match the following image
37. Name the step "create_new_document"

![trigger_5](https://user-images.githubusercontent.com/10964629/178050220-3db52bf3-568d-40b0-b100-2be1bf5f9b10.JPG)

38. Click on the plus sign underneath the trigger step
39. Add a Python step
40. Select "Run Python Code"
41. Name the step "Github_Action"
42. Add the code included in the following image

![trigger_6](https://user-images.githubusercontent.com/10964629/178051934-ef0afb7b-d095-4574-ad8c-7fce78bc9775.JPG)

43. Click on the plus sign underneath the trigger step
44. Add a Python step
45. Select "Run Python Code"
46. Name the step "python" - or anything else you like. Since it's the last step, the name is not important.
47. Add the code included in the following image

![trigger_7](https://user-images.githubusercontent.com/10964629/178052334-a8127e32-ed7b-45e6-b6a9-fa99904cf8d8.JPG)

48. You will need to test each step of the workflow to validate it works correctly
49. Once all steps are validated, click on the "Deploy" button in the top right
50. You will be taken to the "inspect" console that shows a summary of each step and a log of each Webhook request

### Cisco API Console Registration

An account will also need to be created to access the [Cisco API Console](https://apiconsole.cisco.com/).

1. Once logged into the Cisco API Console, click on "My Keys & Apps"
   ![My Keys & Apps](https://github.com/dirflash/psirt-7-day/blob/master/images/keys_apps.JPG)

2. Click on "Register a New Apps
3. Give your application a name
4. Provide an optional description of the application
5. Select "Client Credentials" in the "OAuth2.0 Credentials" section
6. Select the "Cisco PSIRT openVuln API" check box
7. Agree to the "Terms of Service"
8. Click on "Register"

Save the "Key" and "Client Secret" in a secure place. These credentials will need to be added as Github secrets for the Github action to work properly.

### MongoDB

### Github

## Run and test locally

## Requirements to run and test locally

This script requires a Python environment and the libraries included in the [requirements.txt](https://github.com/dirflash/psirt-bot-card/blob/master/requirements.txt) file.

Import requirements file: `pip install -r requirements.txt`

### Configparser to store and access secrets

All the API keys are stored in a config.ini file using [configparser](https://docs.python.org/3/library/configparser.html). Your config.ini file should look like this:

![Sample config.ini file](https://user-images.githubusercontent.com/10964629/179619962-6a2d545b-6e6b-42d7-9d01-cb9722ac1fa0.png)

### Cisco API Console Credentials

Follow the instructions in the "Cisco API Console Registration section"

The generated "Key" and "Client Secret" should be used as the client_id and client_secret objects in psirt.py.

## Usage

```
$  python.exe psirt-bot.py
```

[psirt-bot.py](https://github.com/dirflash/psirt-bot-card/blob/master/psirt-bot.py) is the main script.

It retrieves a calls OAuth Bearer access token, collects the number of active PSIRT listings and the number of PSIRTs that have been updated in the last 7-days.

It then collects Webex App user information stored in the MongoDB instance, and responds to the requester with a report of the PSIRTs that have been updated in the last 7-day, 14-days, or 30-days based on the selection related to the first adaptive card.

If the script is run locally, a CSV file of the report is also generated an placed in the 'reports' folder.

Example conversation in the Webex App:

![conversation](https://user-images.githubusercontent.com/10964629/178044418-a0995e1f-4037-4e31-90ab-b2cc1878302a.JPG)

### Sample report

![sample_report](https://user-images.githubusercontent.com/10964629/178044999-5f1b6ce7-7001-4962-a068-1189d87c4e9a.JPG)

## Usage Walk Through

YouTube ![Walk Through](https://youtu.be/4AVw72WgZ5A) video from a user perspective.

## Bot Workflow

<p align="center">
  <img width="921" height="1344" src="https://user-images.githubusercontent.com/10964629/179082986-db417a65-17f7-4862-8d55-7b4a1ed7fd46.JPG">
</p>

## References

1.  [Webex Developer Platform Documentation](https://developer.webex.com/docs/platform-introduction)

![PSIRT Bot](https://user-images.githubusercontent.com/10964629/172955101-76942969-039e-402a-a1c0-e3ed6c71ab38.png)

# Python PSIRT Bot

---

**In beta!**

### Documentation is hard

**Still working on the documentation. It's not complete, or accurate, at the moment!**

---

# Getting Started

1.  [Problem Statement](#ps)
2.  [Requirements](#requirements-for-running-in-autonomous-bot-mode)
3.  [Workflow Diagram](#workflow)

<a name="ps"></a>

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

<a name="workflow"></a>

## Bot Workflow

<p align="center">
  <img width="921" height="1344" src="https://user-images.githubusercontent.com/10964629/179082986-db417a65-17f7-4862-8d55-7b4a1ed7fd46.JPG">
</p>

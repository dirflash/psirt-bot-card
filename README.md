![PSIRT Bot](https://user-images.githubusercontent.com/10964629/172955101-76942969-039e-402a-a1c0-e3ed6c71ab38.png)

# Python PSIRT Bot

---

**In beta!**

### Documentation is hard

**Still working on the documentation. It's not complete, or accurate, at the moment!**

---

## What problem is this script trying to solve?

Using the [Cisco Security Advisories portal](https://tools.cisco.com/security/center/publicationListing.x), it can be difficult to determine what PSIRT notifications have been updated with new information, affected products, workarounds, and patches.

This project creates a Webex App bot that utilizes Webex Webhooks, [Pipedream workflows](https://pipedream.com), the [Cisco PSIRT openVuln API](https://developer.cisco.com/docs/psirt/?utm_source=devblog&utm_medium=christophervandermade&utm_campaign=securex-page&utm_term=fy22-q2-0000&utm_content=log4j2andpsirt01-ww), MongoDB, and Github Actions to respond to a Webex App message, and deliver an XLXS file of all updated Cisco PSIRT notifications that have occurred in the last 7 days.

This XLXS file will make it easier for a security team to review updated PSIRT information and take any required remediatory actions without the need of setting up a Python environment and creating all the required connections.

## Bot Workflow

<p align="center">
  <img width="587" height="1081" src="https://user-images.githubusercontent.com/10964629/179073560-b026f68b-cfd2-4239-b2de-6a6120941909.JPG">
</p>

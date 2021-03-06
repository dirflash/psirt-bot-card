#!/usr/bin/env python3
"""This script is the logic and brains for psirt-bot. It replies to a Webex App message via webhook from Pipedream. Collects the Cisco PSIRTS updated in the last 7-days from a Google Sheets document (https://github.com/dirflash/psirt-gsheets) and includes the report as a reply back to the Webex App requestor."""

__author__ = "Aaron Davis"
__version__ = "0.1.5"
__copyright__ = "Copyright (c) 2022 Aaron Davis"
__license__ = "MIT License"

import configparser
import logging
from datetime import datetime, date, timedelta, timezone
import os
import sys
import json
from time import time
import requests
import certifi
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(r".\logs\debug.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

KEY = "CI"
if os.getenv(KEY):
    mongoaddr = "cluster0.jzvod.mongodb.net"
    mongodb = "PSIRT"
    mongocollect = "request"
    mongouser = os.environ["mongouser"]
    mongopw = os.environ["mongopw"]
    webex_bearer = os.environ["webex_bearer"]
    psirt_grant = "client_credentials"
    psirt_client_id = os.environ["psirt_client_id"]
    psirt_client_secret = os.environ["psirt_client_secret"]
    gsheet_doc_link_7 = os.environ["gsheet_doc_link_7"]
    gsheet_doc_link_14 = os.environ["gsheet_doc_link_14"]
    gsheet_doc_link_30 = os.environ["gsheet_doc_link_30"]
else:
    config = configparser.ConfigParser()
    config.read("config.ini")
    mongoaddr = config["MONGO"]["mongo_addr"]
    mongodb = config["MONGO"]["mongo_db"]
    mongocollect = config["MONGO"]["mongo_collect"]
    mongouser = config["MONGO"]["user_name"]
    mongopw = config["MONGO"]["password"]
    webex_bearer = config["WEBEX"]["bearer"]
    psirt_grant = config["PSIRT"]["grant_type"]
    psirt_client_id = config["PSIRT"]["client_id"]
    psirt_client_secret = config["PSIRT"]["client_secret"]
    gsheet_doc_link_7 = config["GSHEETS"]["doc_link_7"]
    gsheet_doc_link_14 = config["GSHEETS"]["doc_link_14"]
    gsheet_doc_link_30 = config["GSHEETS"]["doc_link_30"]

MAX_MONGODB_DELAY = 500

Mongo_Client = MongoClient(
    f"mongodb+srv://{mongouser}:{mongopw}@{mongoaddr}/{mongodb}?retryWrites=true&w=majority",
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=MAX_MONGODB_DELAY,
)

db = Mongo_Client[mongodb]
collection = db[mongocollect]
card_counter = db["counter"]

wa_post_msg_url = "https://webexapis.com/v1/messages"
wa_token = f"Bearer {webex_bearer}"
wa_headers = {"Authorization": wa_token, "Content-Type": "application/json"}
wa_msg_body = "Adaptive card response. Open message on a supported client to respond."


pre_record_ids = []
record_ids = []
TOTAL_CHANGED = 0
VALID_COUNT = 0
valid_object_id = []
INVALID_COUNT = 0
invalid_object_id = []


def update_created(recerd, date_string):
    """When the 'createdAt' date is created in Mongo, it is a str. This function changes the
    MongoDB type to 'date'. This is required for a MongoDB index job that purges records
    older than 7-days. This index job is from managing the size of the Mongo database.

    Args:
        record (int): MongoDB record object _id
        date_string (str): The records created time to be converted
    """
    try:
        mydate = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f%z")
        collection.update_one({"_id": recerd}, {"$set": {"createdAt": mydate}})
    except ConnectionFailure as key_error:
        print(key_error)


def get_rm_rpt(entry_id):
    """Get the Webex app room ID for the reply

    Args:
        entry_id (int): MongoDB record object _id

    Returns:
        str: Webex app room ID
    """
    lookup_record = collection.find_one({"_id": entry_id})
    reply_room = lookup_record["Room_Id"]
    report_format = lookup_record["Report_Type"]
    report_time = lookup_record["Report_Time"]
    return reply_room, report_format, report_time


def card_build(cve_count, cve_recent, x):
    """This function builds out the Webex card that will be used as a summary response.

    Args:
        cve_count (int): Total open CVE's
        cve_recent (int): Updated CVE's in last X days
        x (int): Number of days for requested report

    Returns:
        _type_: _description_
    """
    sum_msg = f"  * Number of CVE entries in the last 90-days: {cve_count}\n* Number of CVE entries updated in last {x}-days: {cve_recent}"
    wa_sum_msg = [
        {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.2",
                "body": [
                    {
                        "type": "Image",
                        "url": "https://user-images.githubusercontent.com/10964629/172955101-76942969-039e-402a-a1c0-e3ed6c71ab38.png",
                        "id": "Banner_Image",
                    },
                    {
                        "type": "TextBlock",
                        "text": "PSIRT Summary Report",
                        "wrap": True,
                        "id": "text_block_1",
                    },
                    {
                        "type": "RichTextBlock",
                        "inlines": [
                            {
                                "type": "TextRun",
                                "text": sum_msg,
                            }
                        ],
                        "id": "sum",
                        "spacing": "Small",
                        "separator": True,
                    },
                ],
            },
        }
    ]
    return wa_sum_msg


def psirt_otoken(psirt_f_grant, psirt_f_client_id, psirt_f_client_secret):
    """This function creates the PSIRT OAuth token

    Args:
        grant (str): Token grant type
            (https://raw.githubusercontent.com/api-at-cisco/Images/master/Token_Access.pdf)
        client_id (str): API username
        client_secret (str): API password

    Returns:
        access_token (str): Access token
        token_type (str): Token type ("Bearer")
        token_dies (time): When token expires
    """

    otoken_url = (
        f"https://cloudsso.cisco.com/as/token.oauth2?grant_type={psirt_f_grant}"
        f"&client_id={psirt_f_client_id}&client_secret={psirt_f_client_secret}"
    )

    try:
        otoken_response = requests.request("POST", otoken_url)
        otoken_response.raise_for_status()
    except requests.HTTPError:
        otoken_status = otoken_response.status_code
        if otoken_status == 401:
            logging.error("Invalid API key.")
        elif otoken_status == 404:
            logging.error("Invalid input.")
        elif otoken_status in (429, 443):
            logging.error("API calls per minute exceeded.")
        elif otoken_status == 400:
            logging.error("API bad request.")
        sys.exit(1)

    otoken_data = otoken_response.json()
    otoken_access_token = otoken_data["access_token"]
    otoken_token_type = otoken_data["token_type"]
    otoken_token_expires = otoken_data["expires_in"]
    otoken_token_dies = time() + (otoken_token_expires - 120)

    return (otoken_access_token, otoken_token_type, otoken_token_dies)


def recent_update(verify_cve_date, reported_days):
    """Determines if CVE entry has been updated in last 7 days

    Args:
        verify_cve_date (string): yyyy-mm-ddThh:mm:ss

    Returns:
        bool: True if entry has been updated in last 7 days
    """
    t_index = verify_cve_date.index("T")
    stripped_date = verify_cve_date[:t_index:]
    split_date = tuple(stripped_date.split("-"))
    new_date = date(int(split_date[0]), int(split_date[1]), int(split_date[2]))
    seven_days = date.today() - timedelta(days=reported_days)
    recent = seven_days < new_date
    return recent


def rapid_test(fun_record_ids):
    """Some times multiple requests are received resulting in more than one reply.
    The function will filter out requests made within a 10-second window, suppressing multiple
    replies.

    Args:
        fun_record_ids (int): record_ids to be checked

    Returns:
        int: filtered list of record_ids to respond to.
    """
    logging.info("Before rapid request filter: %s", fun_record_ids)

    dup_check = []
    for count, value in enumerate(fun_record_ids):
        fun_record_id = {"_id": value}
        dup_collect = collection.find_one(fun_record_id)
        created = dup_collect["createdAt"]
        email = dup_collect["User_Id"]
        dup_check.append(
            {"fun_record_id": fun_record_id, "msg_created": created, "email": email}
        )

    len_dup_chk = len(dup_check)

    for _ in reversed(range(len_dup_chk)):
        logging.info("Duplicate primary check index: %s", _)
        source_dup_check = dup_check[_]["fun_record_id"]["_id"]
        source_e_compare = dup_check[_]["email"]
        source_m_compare = dup_check[_]["msg_created"]
        if isinstance(source_m_compare, str):
            update_created(source_dup_check, source_m_compare)
        source_lookup = collection.find_one(fun_record_id)
        source_m_converted = source_lookup["createdAt"]
        sec_dup_check = _ - 1
        logging.info("Duplicate compare check index: %s", sec_dup_check)
        if sec_dup_check >= 0:
            secondary_dup_check = dup_check[sec_dup_check]["fun_record_id"]["_id"]
            sec_e_compare = dup_check[sec_dup_check]["email"]
            sec_m_compare = dup_check[sec_dup_check]["msg_created"]
            if isinstance(sec_m_compare, str):
                update_created(secondary_dup_check, sec_m_compare)
            sec_lookup = collection.find_one(fun_record_id)
            sec_m_converted = sec_lookup["createdAt"]
            if source_e_compare == sec_e_compare:
                logging.info("Duplicate email address found.")
                record_delta = source_m_converted - sec_m_converted
                logging.info("Compare messages record delta: %s", record_delta)
                if record_delta < timedelta(seconds=10):
                    print("within threshold - not a good message")
                    logging.info("Duplicate message sent less than 10 seconds.")
                    tagged_msg_id = fun_record_ids[_]
                    logging.info("Tag msg id  %s as duplicate.", tagged_msg_id)
                    try:
                        dup_msg_id = fun_record_ids[_]
                        collection.update_one(
                            {"_id": dup_msg_id},
                            {"$set": {"response": "duplicate"}},
                        )
                        fun_record_ids.pop(_)
                    except ConnectionFailure as update_err:
                        logging.exception(update_err)
                else:
                    print("exceeded threshold - send good message")

    # end rapid request filter

    logging.info("Deduped message ids: %s", fun_record_ids)
    return fun_record_ids


logging.info("------------------------------------------------------")

# Get PSIRT OAUTH
otoken_token, otoken_type, otoken_expiry = psirt_otoken(
    psirt_grant, psirt_client_id, psirt_client_secret
)


# Get latest PSIRT summary data

TODAY = date.today()
TODAY_STR = str(TODAY)
DELTA = timedelta(days=90)
NINETY_DAYS = TODAY - DELTA
NINETY_DAYS_STR = str(NINETY_DAYS)

psirt_url = (
    f"https://api.cisco.com/security/advisories/all/firstpublished"
    f"?startDate={NINETY_DAYS_STR}&endDate={TODAY_STR}"
)

psirt_token = f"Bearer {otoken_token}"
psirt_headers = {"Authorization": psirt_token}

try:
    psirt_response = requests.request("GET", psirt_url, headers=psirt_headers)
    psirt_response.raise_for_status()
except requests.HTTPError:
    status = psirt_response.status_code
    if status in (401, 403):
        logging.error("Invalid PSIRT API key.")
    elif status == 404:
        logging.error("Invalid PSIRT request input.")
    elif status in (429, 443):
        logging.error("PSIRT API calls per minute exceeded.")
    sys.exit(1)

psirt_json_response = json.loads(psirt_response.text)
cve_entries = psirt_json_response["advisories"]

# End of PSIRT request

new_record = collection.find({"response": {"$exists": False}})
num_records = collection.count_documents({"response": {"$exists": False}})
logging.info("Number of records to check for validity: %s", num_records)

# Get the new record ID's in Mongo
for record in new_record:
    ID = record.get("_id")
    record_id = {"_id": ID}
    pre_record_ids.append(ID)

record_ids = rapid_test(pre_record_ids)
num_records = collection.count_documents({"response": {"$exists": False}})
logging.info("Number of records to check post rapid test: %s", num_records)

# pylint: disable=pointless-string-statement
"""Convert each Mongo 'createdAt' String record to Date object.
This allows the creation of a MongoDB index rule that can clean up records older than a set
number of seconds.
"""
for _ in range(num_records):
    record_index = record_ids[_]
    up_record = collection.find_one({"_id": record_index})
    msg_sent = collection.find(
        {"_id": record_index}, {"msg_sent_status": {"$exists": False}}
    )
    if bool(msg_sent) is True:  # If a msg has already been sent, skip the next steps
        respond = collection.find(
            {"_id": record_index}, {"response": {"$exists": False}}
        )
        date_str = up_record["createdAt"]
        if isinstance(date_str, str):
            update_created(record_index, date_str)
        # if response exists, skip this record
        if bool(respond) is True:
            # bot check
            if up_record["First_Name"] == "bot":
                logging.exception(up_record)
                logging.exception("It's a bot!")
                try:
                    collection.update_one(
                        {"_id": record_index}, {"$set": {"user_type": "Bot"}}
                    )
                except KeyError:
                    try:
                        invalid_object_id.append(record_index)
                        collection.update_one(
                            {"_id": record_index}, {"$set": {"msg": "malformed_msg"}}
                        )
                        collection.update_one(
                            {"_id": record_index},
                            {"$set": {"response": "unknown_request"}},
                        )
                    except ConnectionFailure as key_err:
                        logging.error(key_err)
                invalid_object_id.append(record_index)
                INVALID_COUNT += 1
                TOTAL_CHANGED += 1
            else:
                collection.update_one(
                    {"_id": record_index}, {"$set": {"user_type": "User"}}
                )
                valid_object_id.append(record_index)
                VALID_COUNT += 1
                TOTAL_CHANGED += 1


# Respond to valid requests
for _ in valid_object_id:
    # Get room ID & Report Type
    reply_room_Id, report_type, report_days = get_rm_rpt(_)

    # Get number of CVE's > 90-days and those updated in last {report_days}-days
    CVE_ENTRY_COUNT = 1
    CVE_UPDATED_ENTRIES = 0

    for entry in cve_entries:
        last_updated = entry["lastUpdated"]
        fresh_update = recent_update(
            last_updated, int(report_days)
        )  # function call to get CVE's in {report_days}
        if fresh_update is True:
            CVE_UPDATED_ENTRIES += 1

        CVE_ENTRY_COUNT += 1

    logging.info("Total number of CVE entries: %s", CVE_ENTRY_COUNT)
    logging.info(
        "Number of updated CVE entries in last %s days: %s",
        report_days,
        CVE_UPDATED_ENTRIES,
    )

    # End of conversion

    wa_card_attach = card_build(CVE_ENTRY_COUNT, CVE_UPDATED_ENTRIES, report_days)
    if report_days == "7":
        attach_url = (
            f"https://docs.google.com/spreadsheets/d/e/{gsheet_doc_link_7}/pub?output="
        )
        logging.info("7-day URL")
    if report_days == "14":
        attach_url = (
            f"https://docs.google.com/spreadsheets/d/e/{gsheet_doc_link_14}/pub?output="
        )
        logging.info("14-day URL")
    if report_days == "30":
        attach_url = (
            f"https://docs.google.com/spreadsheets/d/e/{gsheet_doc_link_30}/pub?output="
        )
        logging.info("30-day URL")

    wa_post_payload = json.dumps(
        {
            "roomId": reply_room_Id,
            "markdown": wa_msg_body,
            "attachments": wa_card_attach,
        }
    )

    if report_type == "xlxs":
        file_url = attach_url + "xlsx"
        FILE_TYPE = "xlxs"
    else:
        file_url = attach_url + "csv"
        FILE_TYPE = "csv"
    wa_post_attach = json.dumps(
        {
            "roomId": reply_room_Id,
            "files": [file_url],
        }
    )

    # Send summary card
    post_msg = requests.request(
        "POST",
        wa_post_msg_url,
        headers=wa_headers,
        data=wa_post_payload,
    )
    status_code = post_msg.status_code
    logging.info("Replied to room ID: %s", reply_room_Id)
    logging.info("Attached %s file.", FILE_TYPE)
    logging.info("Replied status code: %s", status_code)

    # Send PSIRT report
    post_attachment = requests.request(
        "POST",
        wa_post_msg_url,
        headers=wa_headers,
        data=wa_post_attach,
    )
    status_code = post_msg.status_code
    logging.info("Attachment sent to room ID: %s", reply_room_Id)
    logging.info("Attachment status code: %s", status_code)

    sent_time = datetime.now(timezone.utc)
    try:
        collection.update_one({"_id": _}, {"$set": {"response": "valid"}})
        collection.update_one({"_id": _}, {"$set": {"msg_sent_status": status_code}})
        collection.update_one({"_id": _}, {"$set": {"msg_sent_time": sent_time}})
    except KeyError:
        try:
            invalid_object_id.append(record_index)
            collection.update_one(
                {"_id": record_index}, {"$set": {"msg": "malformed_msg"}}
            )
            collection.update_one(
                {"_id": record_index}, {"$set": {"response": "unknown_request"}}
            )
        except ConnectionFailure as key_err:
            logging.error(key_err)

# Increment a card counter in a dedicated Mongo collection every time this script runs
counter_id = card_counter.count_documents({"item.counter": {"$exists": False}})
if counter_id == 0:
    card_counter.insert_one({"counter": 1})
    added_rec = card_counter.find_one()
    added_id = added_rec["_id"]
    born_time = datetime.now(timezone.utc)
    card_counter.update_one({"_id": added_id}, {"$set": {"born_date": born_time}})
else:
    odometer = card_counter.find_one()
    update_id = odometer["_id"]
    card_counter.update_one({"_id": update_id}, {"$inc": {"counter": 1}})
    odometer = card_counter.find_one()

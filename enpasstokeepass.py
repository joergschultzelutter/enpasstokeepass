import json
import os
import logging
from pykeepass import PyKeePass
from shutil import copyfile
import base64

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(module)s -%(levelname)s- %(message)s"
)
logger = logging.getLogger(__name__)


def read_enpass_json_file(json_filename: str):

    success: bool = False
    list_lines = None

    # Open the local file and read it

    if os.path.isfile(json_filename):
        try:
            with open(f"{json_filename}", "r") as f:
                if f.mode == "r":
                    list_lines = f.readlines()
                    f.close()
            success = True
        except:
            list_lines = None
    else:
        logger.info(msg=f"File '{json_filename}' does not exist")

    json_content = {}
    if success:
        if list_lines:
            string_lines = " ".join(list_lines)
            json_content = json.loads(string_lines)
    return json_content


if __name__ == "__main__":
    key_categories = ["username", "email", "password", "url"]

    keepass_filename = "/Volumes/Untitled/Passwords.kdbx"
    keepass_password = "1q2w3e4r"
    keepass_keyfile = None
    enpass_export_filename = "/Volumes/Untitled/export.json"

    copyfile("/Volumes/Untitled/leer.kdbx", keepass_filename)
    kp = None

    try:
        kp = PyKeePass(
            filename=keepass_filename,
            password=keepass_password,
            keyfile=keepass_keyfile,
        )
    except:
        logger.info("Cannot open keepass file")
        exit(0)

    # read the enpass JSON file and receive its content as a dictionary
    json_data = read_enpass_json_file(json_filename=enpass_export_filename)

    # start parsing the file
    if "items" in json_data:
        myitems = json_data["items"]

        # iterate through all items from the export file
        for myitem in myitems:
            # This dictionnary contains the "native" keepass fields
            # (username, email, password, url)
            # The very first instance of a field type within the enpass
            # export file is retrieved and assigned. If an export contains
            # e.g. more than one password fields, field 2..n are considered to
            # be regular fields and it is up to the user to maintain them.
            key_fields = {}

            # For all the other fields that either have no specific field
            # type OR are occurrences 2...n of one of those field types
            # we reserve a 2nd dictionary
            value_fields = {}

            # Get the template type (Enpass' product category)
            # if the template type ends with '.default', then this is a category
            # without a subcategory
            template_type = myitem["template_type"]
            _templates = template_type.split(".")
            category = _templates[0]
            subcategory = _templates[1]
            mytitle = myitem["title"]

            # Get any potential notes that are assigned to this item
            # Enpass always provides this information even if there is no data
            # so let's ensure that we flag this as None if no such data exists
            mynotes = myitem["note"] if myitem["note"] != "" else None

            # Check if we have any attachments
            has_attachments = True if "attachments" in myitem else False

            # Check if we deal with a default
            default_category = True if template_type.endswith(".default") else False

            # now iterate through all the individual fields that this record comes with
            if "fields" in myitem:
                myfields = myitem["fields"]
                for myfield in myfields:
                    myvalue = myfield["value"]
                    mytype = myfield["type"]
                    mylabel = myfield["label"]

                    # the JSON export contains fields even if they are empty
                    # so let's ensure that we only process the data if there
                    # actually is something to process
                    if myvalue != "":
                        # is the field type email/username etc AND
                        # we do not have this stored yet
                        # if yes, then let's consider it a key value
                        if mytype in key_categories and mytype not in key_fields:
                            key_fields[mytype] = myvalue
                        # otherwise, add it to the dictionary
                        # note: required improved dupe handling
                        else:
                            if mytype == "totp":
                                mylabel = "otp"
                            value_fields[mylabel] = myvalue
                print(f"Keyfields:{key_fields}")
                print(f"restliche Felder: {value_fields}")

            # try to find the main category group in the keepass file
            # and create it if it does not exist yet
            root_category = kp.find_groups(
                name=category, group=kp.root_group, first=True
            )
            if not root_category:
                root_category = kp.add_group(
                    destination_group=kp.root_group, group_name=category
                )

            # If we deal with a category that comes with a subcategory,
            # then check if that subcategory exists and create it
            # if necessary
            if not default_category:
                sub_category = kp.find_groups(
                    name=subcategory, group=root_category, first=True
                )
                if not sub_category:
                    sub_category = kp.add_group(
                        destination_group=root_category, group_name=subcategory
                    )
            # if our category has no 2nd tier, simply take this as our foundation for
            # creating the entries.
            else:
                sub_category = root_category

            # now extract our special key fields from the dict
            myusername = key_fields["username"] if "username" in key_fields else ""
            mypassword = key_fields["password"] if "password" in key_fields else ""
            myurl = key_fields["url"] if "url" in key_fields else None
            myemail = key_fields["email"] if "email" in key_fields else None
            if mytitle:
                newentry = kp.add_entry(
                    destination_group=sub_category,
                    title=mytitle,
                    username=myusername,
                    password=mypassword,
                    url=myurl,
                    notes=mynotes,
                )
                for value_field in value_fields:
                    newentry.set_custom_property(
                        key=value_field, value=value_fields[value_field]
                    )
                if has_attachments:
                    attachments = myitem["attachments"]
                    for attachment in attachments:
                        myattachmentname = attachment["name"]
                        myattachmentdata = attachment["data"]
                        myattachment = base64.b64decode(myattachmentdata)
                        attachment_id = kp.add_binary(data=myattachment)
                        newentry.add_attachment(
                            id=attachment_id, filename=myattachmentname
                        )

        # Save the keepass database to disc
        kp.save()

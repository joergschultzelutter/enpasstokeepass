#!/opt/local/bin/python
import datetime

# Enpass-to-Keepass converter
# Author: Joerg Schultze-Lutter, 2021
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

#
# This program reads an Enpass JSON export file and converts its contents
# to an existing Keepass file.

import json
import os
import logging
from pykeepass import PyKeePass
from pykeepass import __version__ as pykeepass_version
from shutil import copyfile
import base64
import unicodedata
import argparse
from uuid import UUID
import pytz

pk_reserved_keys = []
pk_reserved_special_keys = ["otp"]

# get the list of reserved keys from pykeepass whereas
# present. This is important if the user runs a pykeepass
# version of 4.0.4 and later.
#
try:
    from pykeepass.entry import reserved_keys as _pk_keys

    pk_reserved_keys = _pk_keys.copy()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(module)s -%(levelname)s- %(message)s"
)
logger = logging.getLogger(__name__)


def read_enpass_json_file(json_filename: str):
    """
    Read the Enpass export file and converts its content to a dictionary

    Parameters
    ==========
    json_filename : 'str'
        file name of the Enpass JSON export file

    Returns
    =======

    Returns a dict, consisting of the the Enpass JSON export content

    """
    list_lines = None

    # Open the local file and read it

    if os.path.isfile(json_filename):
        try:
            with open(f"{json_filename}", "r") as f:
                if f.mode == "r":
                    list_lines = f.readlines()
                    f.close()
        except:
            list_lines = None
    else:
        logger.info(msg=f"File '{json_filename}' does not exist")

    json_content = {}
    # did we receive any content?
    if list_lines:
        # enpass exports single lines; let's join them
        string_lines = " ".join(list_lines)
        # Finally, try to convert the content to a dictionary
        try:
            json_content = json.loads(string_lines)
        except:
            json_content = {}
    return json_content


def remove_control_characters(s: str):
    """
    Removes Unicode control characters from the input string
    (those control characters would result in an import error)

    Parameters
    ==========
    s : 'str'
        our input string

    Returns
    =======
    string without unicode control characters
    """

    return "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")


def is_reserved_word(my_key: str):
    """
    Detects if the key that we are about to write is something
    that is considered as "reserved key" by pykeepass

    Parameters
    ==========
    my_key : 'str'
        the key that we want to check

    Returns
    =======
    'None" if not found, else pykeepass' reserved key
    """

    low_key = my_key.lower()
    lower_reserved_values = [res.lower() for res in pk_reserved_keys]
    if low_key in lower_reserved_values:
        return pk_reserved_keys[lower_reserved_values.index(low_key)]
    else:
        return None


def is_uuid(my_uuid: str):
    """
    Checks if the given string is a uuid

    Parameters
    ==========
    my_uuid : 'str'
        (potential) uuid that we want to check

    Returns
    =======
    'False' -> string is no uuid
    'True" -> string is uuid
    """
    try:
        UUID(my_uuid)
        return True
    except ValueError:
        pass

    return False


def get_command_line_params():
    """
    Gets the program's input parameters

    Parameters
    ==========
        none
    Returns
    =======
        input parameters from command line
    """
    # Get our parameters
    # Syntax: enpasstokeepass <enpass_export_file> <keepass_target_file> [--password] [--keyfile]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "enpassfile", type=argparse.FileType("r"), help="Enpass Export File"
    )

    parser.add_argument(
        "keepassfile", type=argparse.FileType("r"), help="Keepass target file"
    )

    parser.add_argument("--password", default=None, type=str, help="Keepass password")
    parser.add_argument("--keyfile", default=None, type=str, help="Keepass keyfile")

    args = parser.parse_args()

    return (
        args.keepassfile.name,
        args.password,
        args.keyfile,
        args.enpassfile.name,
    )


if __name__ == "__main__":
    # get our command line parameters
    (
        keepass_filename,
        keepass_password,
        keepass_keyfile,
        enpass_export_filename,
    ) = get_command_line_params()

    # Keepass' 'native' core key entries. We also use this table to prevent
    # the creation of 'regular' attributes with these names
    key_categories = ["username", "email", "password", "url"]

    # this is our keepass object
    kp = None

    # try to open the Keepass file
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

    # start the parsing process. Enpass defines the entries as GLOBAL
    # settings, meaning that we will first parse and collect these
    # entries and then later on assign these settings to the Keepass
    # export (whereas present)
    #
    # define an empty tag directory; this will contain
    # the tag uuids and their corresponding human readable name
    # from the export file in case the user has assigned tags
    # to an entry.
    enpass_tag_directory = {}

    # Check if there are any tags in the export and collect the
    # entries wheresas present
    # The UUID will be used to match keepass entry and human readable
    # tag value(s) _OR_ folders (yes, Enpass (ab)uses this structure
    # for two different things. Don't blame me for it :-)
    if "folders" in json_data:
        myitems = json_data["folders"]

        for myitem in myitems:
            if "uuid" in myitem:
                if "title" in myitem:
                    # our entry MIGHT be a tag
                    my_parent_uuid = (
                        myitem["parent_uuid"] if "parent_uuid" in myitem else ""
                    )

                    # The entry seems to be a tag if:
                    # - title is not "Root"
                    # - parent_uuid is empty
                    # If these conditions do not apply, our entry might be a (sub)folder
                    # we will gather these in a different structure in order
                    # to avoid confusion
                    if myitem["title"] != "Root" and my_parent_uuid == "":
                        enpass_tag_directory[myitem["uuid"]] = myitem["title"]

    # start parsing the remainder of the file (our actual data)
    if "items" in json_data:
        myitems = json_data["items"]

        # iterate through all items from the export file
        for myitem in myitems:
            # This dictionary contains the "native" keepass fields
            # (username, email, password, url)
            # The very FIRST instance of a field type within the enpass
            # export file is retrieved and assigned. If an export contains
            # e.g. more than one password fields, field 2..n are considered to
            # be regular fields and it is up to the user to maintain them.
            # Those fields will end up in the value_fields dictionary
            key_fields = {}

            # For all the other fields that either have no specific field
            # type OR are occurrences 2...n of one of those field types
            # we reserve a 2nd dictionary
            value_fields = {}

            # Get the Unix timestamp for when the entry was last
            # updated convert it to a Python DateTime object
            updated_at_ux = myitem["updated_at"]
            updated_at_dt = datetime.datetime.fromtimestamp(updated_at_ux)

            # Get the Unix timestamp for when the entry was
            # created and convert it to a Python DateTime object
            created_at_ux = myitem["createdAt"] if "created_at" in myitem else myitem["updated_at"]
            created_at_dt = datetime.datetime.fromtimestamp(created_at_ux)

            # Get the template type (Enpass' product category)
            # if the template type ends with '.default', then this is a category
            # without a subcategory
            template_type = myitem["template_type"]

            # Check if we deal with a default
            default_category = True if template_type.endswith(".default") else False

            # per issue ticket #7, there might be rare cases where Enpass populates
            # this field with a UUID - mainly because of a previous database import
            # from e.g. Keepass to Enpass. I was unable to reproduce the issue
            # (for my test cases, Enpass had always created separate folders)
            # As a workaround, let's test if the field can be split up and is
            # not a UUID. In any other case, assign a default category to our input
            if "." in template_type and not is_uuid(template_type):
                _templates = template_type.split(".")
                category = _templates[0]
                subcategory = _templates[1]
            else:
                category = "Miscellaneous"
                subcategory = ""
                default_category = False

            # Get title and uuid
            mytitle = myitem["title"]
            myuuid = myitem["uuid"]

            logger.info(f"Processing entry '{mytitle}'")

            # Get any potential notes that are assigned to this item
            # Enpass always provides this information even if there is no data
            # so let's ensure that we flag this as None if no such data exists
            mynotes = myitem["note"] if myitem["note"] != "" else None

            # Check if we have any attachments
            has_attachments = True if "attachments" in myitem else False

            # First start with processing the tags. This is some kind of a backwards
            # approach as the tags are exported AFTER the actual entry
            # Reverse engineering beggars can't be choosers, though
            tags_to_export = []
            if "folders" in myitem:
                for uuid in myitem["folders"]:
                    if uuid in enpass_tag_directory:
                        tags_to_export.append(enpass_tag_directory[uuid])

            # now iterate through all the individual fields that this record comes with
            if "fields" in myitem:
                myfields = myitem["fields"]
                for myfield in myfields:
                    myvalue = myfield["value"]
                    mytype = myfield["type"]
                    mylabel = myfield["label"]
                    myuid = myfield["uid"]

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
                        else:
                            # reflag enpass TOTP entries; Keepass requires this as "otp"
                            # hint: we assume that there is only one totp entry per record
                            if mytype == "totp":
                                mylabel = "otp"
                            # Enpass field names can be empty; if that is the case, use a fixed
                            # prefix and the field's uid as field name
                            if mylabel == "":
                                logger.info(
                                    f"Empty enpass label name '{mylabel}' for entry '{mytitle}' detected; assigning 'empty_enpass_label_{myuid}' to keepass target field"
                                )
                                mylabel = f"empty_enpass_label_{myuid}"
                            else:
                                # label is not empty - this should be our default
                                # If we detect a dupe record, attach the UUID to the label name
                                if mylabel in value_fields:
                                    logger.info(
                                        f"Duplicate enpass label name '{mylabel}' for entry '{mytitle}' detected; attaching UID '{myuid}' to keepass label"
                                    )
                                    mylabel = f"{mylabel}_{myuid}"
                                # now check if we deal with a reserved key. If applicable
                                # AND the field is not of "otp" value, add the UID
                                reserved_key = is_reserved_word(mylabel)
                                if reserved_key:
                                    # now let's check if we need to keep the field 'as is'
                                    # currently, this only applies to OTP entries
                                    if reserved_key not in pk_reserved_special_keys:
                                        logger.info(
                                            f"Detected reserved key '{mylabel}' for entry '{mytitle}'; attaching UID '{myuid}' to keepass label"
                                        )
                                        mylabel = f"{mylabel}_{myuid}"

                            # check if the label that we want to create contains a Keepass keyword
                            # (e.g. password, url). If yes, rename the field accordingly
                            if mylabel.lower() in key_categories:
                                logger.info(
                                    f"Reserved word '{mylabel.lower()}' for entry '{mytitle}' detected; attaching UID '{myuid}' to keepass label"
                                )
                                mylabel = f"{mylabel}_{myuid}"

                            # Remove all potential UTF-8 control characters from the field's value
                            # These settings are not visible in Enpass but would break the Keepass import
                            myvalue = remove_control_characters(myvalue)

                            # if the uuid'ed label is also a dupe, then we give up
                            # This could be enhanced with a more sophisticated key
                            # but as this a quick conversion hack I don't really care
                            if mylabel in value_fields:
                                logger.info(
                                    f"Duplicate enpass label+uuid '{mylabel}' name for entry '{mytitle}' detected; giving up"
                                )
                            else:
                                value_fields[mylabel] = myvalue

            # We have processed the data for one entry - now let's start
            # with writing it to the Keepass file
            #
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
            # if our category has no 2nd tier, simply take the root group as
            # our foundation for creating the entries.
            else:
                sub_category = root_category

            # now extract our special key fields from the dict
            # Username and Password can be empty string if the values are not present
            myusername = key_fields["username"] if "username" in key_fields else ""
            mypassword = key_fields["password"] if "password" in key_fields else ""

            # Per pykeepass, url and email need to be 'None" if not present
            myurl = key_fields["url"] if "url" in key_fields else None
            myemail = key_fields["email"] if "email" in key_fields else None

            # Check if the title already exists in the database
            if mytitle:
                matches = kp.find_entries_by_title(
                    title=mytitle, group=sub_category, first=True
                )
                # We have found a ducplicate - let's add the uuid to the title
                if matches:
                    logger.info(
                        f"Duplicate title '{mytitle}' detected; attaching uuid '{myuuid}' to it"
                    )
                    mytitle = f"{mytitle}_{myuuid}"

                # Check again (potentially with the enhanced title). Create the entry if
                # it is not present in the Keepass database
                matches = kp.find_entries_by_title(
                    title=mytitle, group=sub_category, first=True
                )
                # Still a dupe? Then we give up. This should never happen, though
                if matches:
                    logger.info(
                        f"Duplicate title with uuid '{mytitle}' detected; giving up"
                    )
                else:
                    # Create the Keepass entry
                    newentry = kp.add_entry(
                        destination_group=sub_category,
                        title=mytitle,
                        username=myusername,
                        password=mypassword,
                        url=myurl,
                        notes=mynotes,
                        tags=tags_to_export,
                    )

                    # set the original created_at / updated_at
                    # values from Enpass for our new entry
                    newentry.ctime = created_at_dt.replace(tzinfo=pytz.UTC)
                    newentry.mtime = updated_at_dt.replace(tzinfo=pytz.UTC)

                    # Add the extra properties (if present)
                    for value_field in value_fields:
                        # starting with pykeepass version 4.0.4, several attributes
                        # need to be handled differently
                        #
                        # First check if the key that we are about to write is~
                        # a reserved word. Note that the only remaining
                        # "reserved" key is an OTP entry - all other entries have
                        # already been amended by their respective uid's
                        reserved_key = is_reserved_word(my_key=value_field)

                        # No reserved key? Great - write entry as usual and "as is"
                        if not reserved_key:
                            newentry.set_custom_property(
                                key=value_field, value=value_fields[value_field]
                            )
                        else:
                            # We deal with a reserved key which requires us to invoke
                            # the object's 'setter' method. The ONLY entry that we should
                            # see here is an "otp" entry. Every other reserved key has
                            # already been force-amended with the field's uid value.
                            # Nevertheless, let's keep this method generic in case of
                            # future changes to pykeepass.
                            if reserved_key in pk_reserved_special_keys:
                                setattr(
                                    newentry, reserved_key, value_fields[value_field]
                                )

                    # write the attachments (if present)
                    if has_attachments:
                        attachments = myitem["attachments"]
                        for attachment in attachments:
                            # get the name and the base64-encoded content
                            myattachmentname = attachment["name"]
                            myattachmentdata = attachment["data"]
                            # decode the base64 content
                            myattachment = base64.b64decode(myattachmentdata)
                            # add the decoded content to keepass
                            attachment_id = kp.add_binary(data=myattachment)
                            # assign the file name to the binary and
                            # create the logical connection to the main entry
                            newentry.add_attachment(
                                id=attachment_id, filename=myattachmentname
                            )

        # Finally, save the keepass database to disc
        logger.info("Saving Keepass database")
        kp.save()

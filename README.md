# EnpassToKeepass

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![CodeQL](https://github.com/joergschultzelutter/enpasstokeepass/actions/workflows/codeql.yml/badge.svg)](https://github.com/joergschultzelutter/enpasstokeepass/actions/workflows/codeql.yml)

This program reads an Enpass JSON export file and writes its contents to an existing Keepass file.

Syntax: ```enpasstokeepass [enpass_json_export_file] [existing_keepass_target_file] <--password Keepass_Password> <--keyfile Keepass_Keyfile>```

## Installation
- clone repo
- ```pip install -r requirements.txt```

## Sample usage
The following paragraph describes a sample export from Enpass, following by the respective Keepass import process. I use KeepassXC for the database generation; dependent on your Keepass flavor of choice, your miles may vary. I also do not use a Keepass keyfile for this example.

### Step 1 - Enpass Export

- Open Enpass
- Menu ```File``` ->```Export```
- Create an export of your database. My sample file name will be ```export.json```

### Step 2 - Create Keepass database

- Open KeepassXC
- ```Create new database```
- Leave defaults as is (db name will be ```Passwords.kbdx```)
- Password is ```test1234```
- optional: create an additional key file

### Step 3 - Import process

- Go to console and activate venv, whereas installed
- ```python enpasstokeepass.py --password test1234 export.json Passwords.kdbx```

Output should look like this:

```2023-11-27 17:47:01,270 enpasstokeepass -INFO- Processing entry 'ABC'```

```2023-11-27 17:47:01,276 enpasstokeepass -INFO- Processing entry 'DEF'```

```2023-11-27 17:47:01,281 enpasstokeepass -INFO- Processing entry 'GHI'```

...

```2023-11-27 17:47:04,686 enpasstokeepass -INFO- Saving Keepass database```

Note: unless you see the very last line ("`Saving Keepass database`"), your changes will not be written to the Keepass database.




## In Scope
- creates the (native) Enpass group names in Keepass; e.g. a login item will end up in the login category
- whenever possible, item names (and attributes) are copied as is. If a duplicate entry is detected, the program still tries to write the entry by attaching Enpass' uid/uuid to it.
- supports full transfer of attachments

## Out of scope / Known issues

- little-to-none exception handling. This is a quick hack. It did convert my whole Enpass database without any issues, though. Nevertheless, your miles may vary.
- Garbage-in-garbage-out. For certain entries, Enpass does seem to store fields that are not even visible in the GUI - but are present in the JSON export file. Obviously, these entries will be converted as well. If you start the migration and wonder about extra fields that suddenly appear in the Keepass target file, you may want to have a look at the Enpass export file - those fields are likely in there.
- Enpass always exports ALL fields - regardless of whether the fields have any content or not. This program only converts those entries where the attributes have a value assigned to them. If you create an attribute but don't assign a value to it, that entry will not get converted.
- The category / group names are copied "as is" (based on their Enpass group *type*). You may want to rename these categories once the migration has been completed.
- The program expects an __existing__ Keepass file. It will __not__ create a new file for you. Additionally, I strongly suggest testing the conversion with an empty target database first.
- First-come-first-serve. Enpass permits e.g. multiple 'password' attributes per entry. For each type in (username, email, password, url), this converter uses the very first instance for creating the native Keepass key value. Occurrence 2..n will end up as regular attributes in the Keepass entry - regardless of whether they are e.g. a URL, email address or not. Note that the entries are copied 'as is' (just their respective field values WITHOUT any read protection). You may be forced to manually protect those additional password entries. Neither the Enpass export file gives any indication about their (previous) visibility protection state nor can that status be set via PyKeePass for the additional attributes.
- This program assumes that there will be 0...1 "totp" entries in the Enpass entry. In case Enpass should ever support more than one TOTP setting per entry  (should never happen), only the very last entry survives in the Keepass target file.
- As part of the conversion, all entries will lose their original creation date as it does not seem to be possible to set that value via pykeepass
- The Keepass expiration date cannot be set as there is no distinct Enpass data type for it
- Enpass groups/sections within an enpass entry are NOT transferred to Keepass. Reason: they are exported as "empty" entries and apart from their order enumeration, there is no connection to the fields that are part of Enpass' export.
- The export process will always write NEW entries to Keepass. EXISTING entries will NOT be updated; if a key name conflict is detected (e.g. a key is to be written to Keepass, but it already exists), the code will attach the internal enpass UID to that field name.
- If your Enpass database contains entries which use 'escaped' content (e.g `=\"`) as title information, `pykeepass`' underlying XML processor is likely going to choke. Please ensure to provide clean data sources.
- If you import a foreign password manager file to Enpass and this file has subfolder names which are not natively supported by Enpass, the Enpass export will still contain these folders. Dependent on what initial password manager was used as source, Enpass will either recognise these as folders and assign Tags to your entries - OR it will assign a UUID reference as Enpass template type. Both options are currently unsupported and will result in `enpasstokeepass` assigning a `Miscellaneous` category to these entries.

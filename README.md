# EnpassToKeepass

This program reads an Enpass JSON export file and writes its contents to an existing Keepass file.

Syntax: ```enpasstokeepass [enpass_json_export_file] [existing_keepass_target_file] <--password Keepass_Password> <--keyfile Keepass_Keyfile>```

## In Scope

- creates the (native) Enpass group names in Keepass; e.g. a login item will end up in the login category.
- whenever possible, item names (and attributes) are copied as is. If a duplicate entry is detected, the program still tries to write the entry by attaching Enpass' uid/uuid to it.
- supports transfer of attachments

## Out of scope / Known issues

- little to none exception handling. This is a quick hack. It did convert my whole Enpass database without any issues, though. Nevertheless, your miles may vary.
- Garbage-in-garbage-out. For certain entries, Enpass does seem to store fields that are not even visible in the GUI - but are present in the JSON export file. Obviously, these entries will be converted as well. If you start the migration and wonder about extra fields that suddenly appear in the Keepass target file, you may want to have a look at the Enpass export file - those fields are likely in there.
- Enpass always exports ALL fields - regardless of whether the fields have any content or not. This program only converts those entries where the attributes have a value assigned to them. If you create an attribute but don't assign a value to it, that entry will not get converted.
- The category / group names are copied "as is" (based on their group *type*). You may want to rename these categories once the migration has been completed.
- The program expects an __existing__ Keepass file. It will __not__ create a new file for you. I strongly suggest testing the conversion with an empty target database first.
- First-come-first-serve. Enpass permits e.g. multiple 'password' attributes per entry. For each type in (username, email, password, url), this converter uses the very first instance for creating the native Keepass key value. Occurrence 2..n will end up as regular attributes in the Keepass entry - regardless of whether they are e.g. a URL, email address or not. Note that the entries are copied 'as is', especially w.r.t. their visibility state. You may be forced to manually protect those additional password entries.
- This program assumes that there will be 0...1 "totp" entries in the Enpass entry. In case Enpass should ever support more than one TOTP setting per entry, only the very last entry survives (note that this should never happen)
- As part of the conversion, all entries will lose their original creation date as it does not seem to be possible to set value this via pykeepass
- The Keepass expiration date cannot be set as there is no distinct Enpass data type for it

## Dependencies

- [pykeepass](https://pypi.org/project/pykeepass/)

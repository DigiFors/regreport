# regreport
A Python tool that reads user and system data from registry hives. Requires the SAM, SYSTEM and SOFTWARE registry hives. Can not be used to analyze a running system.

## Usage
`regreport.py path_to_files` (if all hives have their default names, and are in the same directory)
or
`regreport.py path_to_SAM path_to_SYSTEM path_to_SOFTWARE``

## Function
The function `get_registry_data` is reusable. It requires three arguments which are the file names of the SAM, the SYSTEM and the SOFTWARE hive. It returns two dictionaries, one with system data, one with user data. The user dictionary has a key for every user ID, and another dictionary for further data.

## Dependencies
python-registry: http://www.williballenthin.com/registry/

## Contact
Contact us at info@digifors.de.

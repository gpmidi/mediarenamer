mediarenamer
============

Python script to match identical files with different names and/or directory structures

Usage: mediarenamer.py (-d|--digest) PATH 
 mediarenamer.py (-r|--rename) [-t|--test] SOURCEPATH DESTINATIONPATH

Options:
  --version        show program's version number and exit
  -h, --help       show this help message and exit
  -t, --test       do not perform rename; only print output
  -d, --digest     generate new md5 hash digest
  -r, --rename     compare digests and rename files at destination
  --md5app=MD5APP  The path to an external MD5 checksum program. Use "" to
                   disable external MD5 app usage. [default: /usr/bin/md5sum]
  -v, --verbose    Enable verbose output. [default: False]


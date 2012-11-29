#!/usr/bin/python
""" This script will compare two media directories (source and
destination), create an md5sum digest of all files in both,
and rename files in the destination, if any checksums match.

By rickatnight11

Patches by: 
- Paulson McIntyre (GpMidi) <paul@gpmidi.net>

"""
# Logging S&C
import logging
logging.basicConfig()

# Default logging level.  
# DEFAULT_LOGGING_LEVEL = logging.DEBUG
DEFAULT_LOGGING_LEVEL = logging.INFO
# DEFAULT_LOGGING_LEVEL = logging.WARN
# DEFAULT_LOGGING_LEVEL = logging.ERROR

log = logging.getLogger("MediaRenamer")
log.setLevel(DEFAULT_LOGGING_LEVEL)

log.debug('Inited logging')

import sys
import os
from optparse import OptionParser
import hashlib
import re
import subprocess

# TODO: Move the / to the path concatenation. Also change to use os.path.join. 
digestfilename = '/md5digest.txt'
DEBUG = True
test = False
duplicate = False
action = ""
sourcepath = ""
destinationpath = ""
digestpath = ""
sourcedigest = {}
destinationdigest = {}
# Path to the MD5 checksum CLI app
md5app = '/usr/bin/md5sum'

# Grab an MD5 with a space on the end
RE_MD5HASH = re.compile(r'([a-fA-F\d]{32})\s.+')
# Grab an MD5 only
RE_MD5HASH_PULL = re.compile(r'([a-fA-F\d]{32})')

# Exceptions
class FileReadError(IOError):
    """ Couldn't find the given file or no permissions to access it """

class ExternalHashError(RuntimeError):
    """ Failed to use an external app to hash a file. """

class ExternalHashValidationError(ValueError):
    """ Couldn't find an MD5 checksum in the MD5 checksum app output """


def ProcessArgs():
    
    global test
    global action
    global sourcepath
    global destinationpath
    global digestpath
    global md5app
    
    # Define option/argument parser
    parser = OptionParser(
                          usage = 'usage: %prog (-d|--digest) PATH \n %prog (-r|--rename) [-t|--test] SOURCEPATH DESTINATIONPATH',
                          version = '%prog 0.1',
                          )
    parser.add_option(
                      '-t',
                      '--test',
                      action = 'store_true',
                      dest = 'test',
                      help = 'do not perform rename; only print output',
                      )
    parser.add_option(
                      '-d',
                      '--digest',
                      action = 'store_true',
                      dest = 'digest',
                      help = 'generate new md5 hash digest',
                      )
    parser.add_option(
                      '-r',
                      '--rename',
                      action = 'store_true',
                      dest = 'rename',
                      help = 'compare digests and rename files at destination',
                      )
    parser.add_option(
                      '--md5app',
                      action = 'store',
                      dest = 'md5app',
                      default = md5app,
                      help = 'The path to an external MD5 checksum program. Use "" to disable external MD5 app usage. [default: %default]',
                      )
    parser.add_option(
                      '-v',
                      '--verbose',
                      action = 'store_true',
                      dest = 'verbose',
                      default = False,
                      help = 'Enable verbose output. [default: %default]',
                      )    
        
    (options, args) = parser.parse_args()
    log.debug('Parsed opts')
    
    if options.verbose:
        log.setLevel(logging.DEBUG)
        log.debug("Verbose logging enabled")
        
    test = options.test
    log.debug('Test: %r', test)
    
    # Save MD5 checksum app, if defined. 
    md5app = options.md5app
    log.debug('MD5 app: %r', md5app)
    
    # Check desired action, digest or rename
    if options.digest and options.rename:
        parser.error("Digest and Rename actions are mutually exclusive!")
    elif options.digest:
        action = "digest"
        if len(args) < 1:
            parser.error("Please provide a path!")
        elif len(args) > 1:
            parser.error("Too many arguments provided!")
        digestpath = args[0]
        if not CheckPath(digestpath):
            parser.error("Failed to check path!")
        if test:
            log.warn("Ignoring unneeded argument, --test/-t.")
    elif options.rename:
        action = "rename"
        # Check for both paths
        if len(args) < 2:
            parser.error("Please provide both source and destination paths!")
        elif len(args) > 2:
            parser.error("Too many arguments provided!")
        sourcepath = args[0]
        destinationpath = args[1]
        if not CheckPath(sourcepath):
            parser.error("Failed to check source path!")
        elif not CheckPath(destinationpath):
            parser.error("Failed to check destination path!")
    else:
        parser.error("Must select either digest or rename!")
    
    
def CheckPath(path):
    try:
        if os.path.exists(path):
            return True
    except:
        log.error("Error checking path: " + path)
        return False


def ReadDigest(path):
    if not CheckPath(path + digestfilename):
        return False
    
    digest = {}
    try:
        f = open(path + digestfilename, 'r')
        while 1:
            lines = f.readlines(100000)
            if not lines:
                break
            for line in lines:
                line = line.rstrip('\n')
                if RE_MD5HASH.match(line):
                    split = line.split(' ', 1)
                    if digest.has_key(split[0]):
                        log.warn('Duplicate files found')
                        log.warn(split[0] + ' ' + split[1] + ' (Skipping)')
                        log.warn(split[0] + ' ' + digest[split[0]] + ' (Keeping)')
                    else:
                        digest[split[0]] = split[1]
                        log.debug('Read in MD5 hash for ' + split[1] + ': ' + split[0])
                else:
                    log.warn('Skipping invalid digest line: ' + line)
        f.close() 
            
    except:
        log.error('Error reading digest!')
        return False
    return digest


def _GenerateMd5PurePy(path):
    """Compute md5 hash of the specified file
    m = hashlib.md5()
    try:
        fd = open(path,"rb")
    except IOError:
        print "Unable to open the file in readmode:", path
        return
    content = fd.readlines()
    fd.close()
    for eachLine in content:
        if excludeLine and eachLine.startswith(excludeLine):
            continue
        m.update(eachLine)
    m.update(includeLine)
    return m.hexdigest()"""
    csize = 4096
    md5sum = hashlib.md5()
    
    log.debug('Doing pure-python MD5 with a chunk size of %d', csize)
    
    with open(path, 'rb') as f:
        block = f.read(csize)
        while block:
            md5sum.update(block)
            block = f.read(csize)
    
    log.debug('Done generating digest')
    return md5sum.hexdigest()


def _GenerateMd5External(path):
    """ Use an external MD5 hashing app to generate 
    the MD5 checksum. May be faster than the pure-python
    approach. 
    """
    assert os.access(path, os.R_OK)
    assert os.access(md5app, os.R_OK | os.X_OK)
    
    log.debug('Doing external hash of %r using %r', path, md5app)
    
    cmdline = [md5app, path]
    
    log.debug('Command line: %r', cmdline)
    
    prehash = ''
    p = subprocess.Popen(cmdline, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    while True:
        rc = p.poll()
        prehash += p.stdout.read()
        if rc is not None:
            break
    # Validate return code
    if rc == 0:
        # Validate the hash
        m = RE_MD5HASH_PULL.findall(prehash)
        if len(m) == 1:
            # Have a valid hash
            log.debug('Done generating hash %r', m[0])
            return m[0]
        elif len(m) > 1:
            # Multiple matches
            log.warn("Found %d MD5s in %r. Not sure which to use. " , len(m), prehash)
            raise ExternalHashValidationError, "Found %d MD5s in %r. Not sure which to use. " % (len(m), prehash)
        else:
            # Invalid hash
            log.warn("Couldn't find a valid hash in %r", prehash)
            raise ExternalHashValidationError, "Couldn't find a valid hash in %r" % prehash
    else:
        log.warn("%r exited with a return code of %d", md5app, rc)
        raise ExternalHashError, "%r exited with a return code of %d" % (md5app, rc)
        
    
def GenerateMd5(path):
    """ Return the MD5 checksum for the given file. The
    hash result should be in a 32 char string in hex format. 
    """
    log.debug('Going to hash %r', path)
    if not os.access(path, os.R_OK):
        log.error("Couldn't read file %r", path)
        raise FileReadError, "Couldn't read %r" % path
    
    # TODO: Add debug logging to this
    if os.access(md5app, os.R_OK | os.X_OK):
        try:
            return _GenerateMd5External(path = path)
        except Exception, e:
            log.exception('External MD5 failed, falling back to pure-python')
            return _GenerateMd5PurePy(path = path)
    else:
        return _GenerateMd5PurePy(path = path)
        
        
def CreateDigest(path):
    
    # Check that path exists and is writable
    if not CheckPath(path):
        sys.exit()
    if not os.access(path, os.W_OK):
        log.error('Cannot write digest to ' + path)
        sys.exit()
    if not os.access(path, os.R_OK):
        log.error('Cannot read from ' + path)
        sys.exit()
        
    # Check for existing digest
    if os.path.exists(path + digestfilename):
        log.error('Digest already exists at ' + path + digestfilename)
        sys.exit()
           
    
    # Include switch in case of duplicate files
    global duplicate
    
    # Create digest dictionary
    digest = {}
    
    # Generate list of files
    files = os.walk(path)
    
    # Create populate digest dictionary with md5 hash info
    for entry in files:
        if len(entry[2]) > 0:
            for tempfile in entry[2]:
                
                # Absolute file path (only used to generate md5 hash)
                newfile = os.path.join(entry[0], tempfile)
                
                # Relative file path (saved to digest)
                newfilename = os.path.relpath(newfile, path)
                
                # Generate md5sum hash
                md5sum = GenerateMd5(newfile)
                
                # Check for duplicates
                if digest.has_key(md5sum):
                    log.warn('Duplicate files found:')
                    log.warn(md5sum + ' ' + newfile + ' (Skipping)')
                    log.warn( md5sum + ' ' + digest[md5sum] + ' (Keeping)')
                    duplicate = True
                else:
                    digest[md5sum] = newfilename
                    log.debug('MD5 hash for \'' + newfilename + '\': ' + md5sum)
                    try:
                        digestfile = open(path + digestfilename, 'a')
                        digestfile.write(md5sum + ' ' + newfilename + '\n')
                        digestfile.close()
                    except:
                        log.error('Issues accessing the path to write the digest.  Aborting!')
                        sys.exit()
    if len(digest) == 0:
        log.error('No files found!')
    else:
        log.info('Created digest out of ' + str(len(digest)) + ' files.')
        log.debug('Digest location: ' + path)       
                
def Rename(torename, path):
    
    renamed = 0
    
    for i in torename:
        oldname = os.path.abspath(os.path.join(path, i[1]))
        newname = os.path.abspath(os.path.join(path, i[2]))
        
        # Check if file exists at path
        if not os.path.exists(oldname):
            log.warn('ERROR: File \'' + oldname + '\' doesn\'t exist!  Skipping!')
        # elif not os.access(i[1], os.W_OK):
        #    print 'ERROR: Cannot access file  for writing! Skipping!'
        else:
            os.rename(oldname, newname)
            renamed += 1
            log.debug('Renamed \'' + oldname + '\' to \'' + newname + '\'')
    
    log.info('Renamed ' + str(renamed) + ' files!')


def CompareDigests():
    if len(sourcedigest) == 0:
        log.error('No files found in source digest! Aborting...')
        return False
    elif len(destinationdigest) == 0:
        log.error('No files found in destination digest! Aborting...')
        return False
    
    torename = []
    skipped = []
    destinationskipped = []
    
    # Iterate through destination digest to look for matching md5 hashes in source digest
    for i in destinationdigest:
        # Match
        if sourcedigest.has_key(i):
            # Only add to rename list, if the filenames are different
            if os.path.basename(destinationdigest[i]) != os.path.basename(sourcedigest[i]):
                newfilename = os.path.basename(sourcedigest[i])
                torename.append((i, destinationdigest[i], os.path.join(os.path.dirname(sourcedigest[i]), newfilename)))
                del sourcedigest[i]
            # Filenames match, so add to skip list
            else:
                skipped.append((i, sourcedigest[i], destinationdigest[i]))
                del sourcedigest[i]
        # No match, so added to destination skip list
        else:
            destinationskipped.append(i)
    
    log.debug('Compare complete!')
    log.debug('')
    
    # Print results
    log.info('To be renamed: (' + str(len(torename)) + ')')
    log.info('--------------')
    for i in torename:
        log.info('[' + i[0] + '] \'' + i[1] + '\' to \'' + i[2] + '\'')
    log.info('')
    
    log.info('Skipped due to filename match: (' + str(len(skipped)) + ')')
    log.info('------------------------------')
    for i in skipped:
        log.info('[' + i[0] + '] \'' + i[1] + '\' to \'' + i[2] + '\'')
    log.info('')
    
    log.info('Skipped extra files in destination: (' + str(len(destinationskipped)) + ')')
    log.info('-----------------------------------')
    for i in destinationskipped:
        log.info('[' + i + '] ' + destinationdigest[i])
    log.info('')
    
    log.info('Source files missing from destination: (' + str(len(sourcedigest)) + ')')
    log.info('--------------------------------------')
    for i in sourcedigest:
        log.info('[' + i + '] \'' + sourcedigest[i])
    
    if not test:
        log.info('Performing rename!')
        Rename(torename, destinationpath)
    
    return True


# Main program
ProcessArgs()

# Generate digest
if action == "digest":
    CreateDigest(digestpath)

# Compare digests and rename
elif action == "rename":
    sourcedigest = ReadDigest(sourcepath)
    if not sourcedigest:
        log.error('EXITING ON SOURCE!')
        sys.exit()
    destinationdigest = ReadDigest(destinationpath)
    if not destinationdigest:
        log.error('EXITING ON DESTINATION!')
        sys.exit()
    
    CompareDigests()


#!/usr/bin/python
#
#This code is not bound by any license or copyright and has no restrictions of its use.
#I am not liable for any damage, as a result of using this script.  The user is responsible
#for any outcome from using this script.
# 
#This script will compare two media directories (source and
#destination), create an md5sum digest of all files in both,
#and rename files in the destination, if any checksums match.


import sys
import os
from optparse import OptionParser
import hashlib
import re

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

RE_MD5HASH = re.compile(r'([a-fA-F\d]{32})\s.+')

def ProcessArgs():
    
    global test
    global action
    global sourcepath
    global destinationpath
    global digestpath
    
    #Define option/argument parser
    parser = OptionParser(usage='usage: %prog (-d|--digest) PATH \n %prog (-r|--rename) [-t|--test] SOURCEPATH DESTINATIONPATH', version='%prog 0.1')
    parser.add_option('-t', '--test', action='store_true', dest='test', help='do not perform rename; only print output')
    parser.add_option('-d', '--digest', action='store_true', dest='digest', help='generate new md5 hash digest')
    parser.add_option('-r', '--rename', action='store_true', dest='rename', help='compare digests and rename files at destination')
        
    (options, args) = parser.parse_args()
    
    test = options.test
    
    #Check desired action, digest or rename
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
            print "Ignoring unneeded argument, --test/-t."
    elif options.rename:
        action= "rename"
        #Check for both paths
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
        print "Error checking path: " + path
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
                        print 'Duplicate files found'
                        print split[0] + ' ' + split[1] + ' (Skipping)'
                        print split[0] + ' ' + digest[split[0]] + ' (Keeping)'
                    else:
                        digest[split[0]] = split[1]
                        if DEBUG:
                            print 'DEBUG: Read in MD5 hash for ' + split[1] + ': ' + split[0]
                else:
                    print 'Skipping invalid line: ' + line
        f.close() 
            
    except:
        print 'Error reading digest!'
        return False
    return digest

def GenerateMd5(path):
    
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
    
    with open(path, 'rb') as f:
        block = f.read(csize)
        while block:
            md5sum.update(block)
            block = f.read(csize)
    
    return md5sum.hexdigest()
        
def CreateDigest(path):
    
    #Check that path exists and is writable
    if not CheckPath(path):
        sys.exit()
    if not os.access(path, os.W_OK):
        print 'Cannot write digest to ' + path
        sys.exit()
    if not os.access(path, os.R_OK):
        print 'Cannot read from ' + path
        sys.exit()
        
    #Check for existing digest
    if os.path.exists(path + digestfilename):
        print 'Digest already exists at ' + path + digestfilename
        sys.exit()
           
    
    #Include switch in case of duplicate files
    global duplicate
    
    #Create digest dictionary
    digest = {}
    
    #Generate list of files
    files = os.walk(path)
    
    #Create populate digest dictionary with md5 hash info
    for entry in files:
        if len(entry[2]) > 0:
            for tempfile in entry[2]:
                
                #Absolute file path (only used to generate md5 hash)
                newfile = os.path.join(entry[0],tempfile)
                
                #Relative file path (saved to digest)
                newfilename = os.path.relpath(newfile, path)
                
                #Generate md5sum hash
                md5sum = GenerateMd5(newfile)
                
                #Check for duplicates
                if digest.has_key(md5sum):
                    print 'Duplicate files found:'
                    print md5sum + ' ' + newfile + ' (Skipping)'
                    print md5sum + ' ' + digest[md5sum] + ' (Keeping)'
                    duplicate = True
                else:
                    digest[md5sum] = newfilename
                    if DEBUG:
                        print 'DEBUG: MD5 hash for \'' + newfilename + '\': ' + md5sum
                    try:
                        digestfile = open(path + digestfilename, 'a')
                        digestfile.write(md5sum + ' ' + newfilename + '\n')
                        digestfile.close()
                    except:
                        print 'Issues accessing the path to write the digest.  Aborting!'
                        sys.exit()
    if len(digest) == 0:
        print "No files found!"
                
def Rename(torename, path):
    
    renamed = 0
    
    for i in torename:
        oldname = os.path.abspath(os.path.join(path, i[1]))
        newname = os.path.abspath(os.path.join(path, i[2]))
        
        #Check if file exists at path
        if not os.path.exists(oldname):
            print 'ERROR: File \'' + oldname + '\' doesn\'t exist!  Skipping!'
        #elif not os.access(i[1], os.W_OK):
        #    print 'ERROR: Cannot access file  for writing! Skipping!'
        else:
            os.rename(oldname, newname)
            renamed += 1
            if DEBUG:
                print 'DEBUG: Renamed \'' + oldname + '\' to \'' + newname + '\''
    
    print 'Renamed ' + str(renamed) + ' files!'

def CompareDigests():
    if len(sourcedigest) == 0:
        print 'No files found in source digest! Aborting...'
        return False
    elif len(destinationdigest) == 0:
        print 'No files found in destination digest! Aborting...'
        return False
    
    torename = []
    skipped = []
    destinationskipped = []
    
    #Iterate through destination digest to look for matching md5 hashes in source digest
    for i in destinationdigest:
        #Match
        if sourcedigest.has_key(i):
            #Only add to rename list, if the filenames are different
            if os.path.basename(destinationdigest[i]) != os.path.basename(sourcedigest[i]):
                newfilename = os.path.basename(sourcedigest[i])
                torename.append((i, destinationdigest[i], os.path.join(os.path.dirname(sourcedigest[i]), newfilename)))
                del sourcedigest[i]
            #Filenames match, so add to skip list
            else:
                skipped.append((i, sourcedigest[i], destinationdigest[i]))
                del sourcedigest[i]
        #No match, so added to destination skip list
        else:
            destinationskipped.append(i)
    
    if DEBUG:
        print 'Compare complete!'
        print ''
    
    #Print results
    print 'To be renamed: (' + str(len(torename)) + ')'
    print '--------------'
    for i in torename:
        print '[' + i[0] + '] \'' + i[1] + '\' to \'' + i[2] +'\''
    print ''
    
    print 'Skipped due to filename match: (' + str(len(skipped)) + ')'
    print '------------------------------'
    for i in skipped:
        print '[' + i[0] + '] \'' + i[1] + '\' to \'' + i[2] +'\''
    print ''
    
    print 'Skipped extra files in destination: (' + str(len(destinationskipped)) + ')'
    print '-----------------------------------'
    for i in destinationskipped:
        print '[' + i + '] ' + destinationdigest[i]
    print ''
    
    print 'Source files missing from destination: (' + str(len(sourcedigest)) + ')'
    print '--------------------------------------'
    for i in sourcedigest:
        print '[' + i + '] \'' + sourcedigest[i]
    
    if not test:
        print 'Performing rename!'
        Rename(torename, destinationpath)
    
    return True


#Main program
ProcessArgs()

#Generate digest
if action == "digest":
    CreateDigest(digestpath)

#Compare digests and rename
elif action == "rename":
    sourcedigest = ReadDigest(sourcepath)
    if not sourcedigest:
        print 'EXITING ON SOURCE!'
        sys.exit()
    destinationdigest = ReadDigest(destinationpath)
    if not destinationdigest:
        print 'EXITING ON DESTINATION!'
        sys.exit()
    
    CompareDigests()


#!/usr/bin/python2
# coding: utf-8
# vtscantar - check the contents of a tar file against Virustotal by hash (without uploading)
# Based on: https://www.guyrutenberg.com/2009/04/29/tarsum-02-a-read-only-version-of-tarsum/
# Written for triaging dumps taken from HTTPFileServer boxes using hfsdump.
# I decided for various reasons to NOT upload the file contents to virustotal...
import requests
import tarfile
import hashlib
import json
import sys

apikey="GET YOUR OWN"


def tarsum(archive_file):
    """
This function heavily based on tarsum, with some modifications. 
returns an array of... "file, hash" kinda objects.
    """
    print "Scanning: %s" %(archive_file)
    try:
        tar = tarfile.open(mode="r|*", fileobj=open(archive_file, "r"))
    except Exception, e:
        print e
    chunk_size = 100*1024
    hashes = []
    for member in tar:
        if not member.isfile():
            continue
        f = tar.extractfile(member)
        h = hashlib.new("sha256")
        data = f.read(chunk_size)
        while data:
            h.update(data)
            data = f.read(chunk_size)
        hash2file = {member.name: h.hexdigest()}
        hashes.append(hash2file)
    return hashes

def vtcheck(file_hash):
	# kludges ahead!
    # checks if a hash is present in virustotal
    endpoint = "https://www.virustotal.com/vtapi/v2/file/report"
    try:
        params = {'apikey': apikey, 'resource': file_hash}
        r = requests.post(url=endpoint, data=params)
    except Exception, e:
        print e
    try:
        fuckingjson = json.loads(r.text)
        totalscanners = fuckingjson['total']
        totalhits = fuckingjson['positives']
    except Exception, e:
        return 0,0 # for now
    return totalscanners, totalhits
    
def tarcheck(archive_file):
    hashes = tarsum(archive_file)
    for hash2file in hashes:
		# WARNING: KLUDGE AHEAD
        filename, file_hash = hash2file.items()[0]
        scanners, hits = vtcheck(file_hash)
        if int(hits) > 0:
            print "Infected File: %s -> SHA256sum: %s -> VirusTotal: %s/%s" %(filename, file_hash, hits, scanners)
        else:
            pass
    
def main(args):
    if len(args) != 2:
        sys.exit("use: %s /path/to/files.tar" %(args[0]))
    tarcheck(archive_file=args[1])
    
    
if __name__ == "__main__":
    main(args=sys.argv)

# vtscantar
Check the hashes of files inside a tar file on VirusTotal

You will need a virustotal API key.

I wrote this to rapidly triage dumps made using [hfsdump](https://github.com/0x27/hfsdump) of HFS servers so I could find malware samples or interesting places to explore.

Example Use:
```
$ python vtscantar/vtscantar.py ./hfsdown/output/mirror-118.193.208.65.tar 
Scanning: ./hfsdown/output/mirror-118.193.208.65.tar
Infected File: servertools.zip -> SHA256sum: 4d834ad218133584258a9edc36b48d2a31fb73fca9804d967b996700d1a4c09c -> VirusTotal: 35/54
$ python vtscantar/vtscantar.py ./hfsdown/output/mirror-122.114.56.242.tar 
Scanning: ./hfsdown/output/mirror-122.114.56.242.tar
Infected File: FunCTion.exe -> SHA256sum: d96b1c938787c76ccb3536d522c828244fd2783732b570ded90577fe7ccaf9c6 -> VirusTotal: 46/57
Infected File: server.exe -> SHA256sum: e110990a7f629e6c0f77ce1909a9ec0a9978f58f754975619bcdaa62b72c29c5 -> VirusTotal: 47/57
$ python vtscantar/vtscantar.py ./hfsdown/output/mirror-123.184.40.109.tar 
Scanning: ./hfsdown/output/mirror-123.184.40.109.tar
Infected File: im666.exe -> SHA256sum: b69469b486ceda6163f077a35e2a371ce277756c737723f3b3450398f851754d -> VirusTotal: 42/54
$
```

Licence: MIT Licence

Bugs: Harass me on twitter: @info_dox or leave issues on the tracker.

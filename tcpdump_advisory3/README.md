# IBM SECURITY ADVISORY

First Issued: Wed Nov  8 09:27:01 CST 2017 

Updated: Wed Feb 28 09:33:13 CST 2018 

Update: Corrected the APARs listed under the APAR section.

The most recent version of this document is available here:

<http://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory3.asc>
<https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory3.asc>
<ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory3.asc>

# Security Bulletin

Vulnerabilities in tcpdump affect AIX

Note: See section IV for full CVE details.

# SUMMARY

There are multiple vulnerabilities in tcpdump that impact AIX. 

## AFFECTED PRODUCTS AND VERSIONS
 
* AIX  5.3, 6.1, 7.1, 7.2
* VIOS 2.2
        
The following fileset levels are vulnerable:
        
key_fileset = aix
        
| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.server | 5.3.12.0 | 5.3.12.6 | key_w_fs |
| bos.net.tcp.server | 6.1.9.0 | 6.1.9.300 | key_w_fs |
| bos.net.tcp.server | 7.1.3.0 | 7.1.3.49 | key_w_fs |
| bos.net.tcp.server | 7.1.4.0 | 7.1.4.32 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.0.0 | 7.2.0.3 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.1.0 | 7.2.1.1 | key_w_fs |
        
 
Note: To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's
guide.

Example:  

```
  lslpp -L | grep -i bos.net.tcp.server 
```


## II. REMEDIATION

### A. FIXES

Fixes are available.

The fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_fix3.tar>
* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_fix3.tar>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_fix3.tar>

The links above are to a tar file containing this signed
advisory, interim fixes, and OpenSSL signatures for each interim fix.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.


| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 5.3.12.9 | IV94729m9a.171009.epkg.Z | key_w_fix |
| 6.1.9.8 | IV94728mAa.171008.epkg.Z | key_w_fix |
| 6.1.9.9 | IV94728mAa.171008.epkg.Z | key_w_fix |
| 6.1.9.10 | IV94728mAa.171008.epkg.Z | key_w_fix |
| 7.1.3.7 | IV94727m9a.171009.epkg.Z | key_w_fix |
| 7.1.3.8 | IV94727m9a.171009.epkg.Z | key_w_fix |
| 7.1.3.9 | IV94727m9a.171009.epkg.Z | key_w_fix |
| 7.1.4.3 | IV94726m5a.171009.epkg.Z | key_w_fix |
| 7.1.4.4 | IV94726m5a.171009.epkg.Z | key_w_fix |
| 7.1.4.5 | IV94726m5a.171009.epkg.Z | key_w_fix |
| 7.2.0.3 | IV94724m5a.171009.epkg.Z | key_w_fix |
| 7.2.0.4 | IV94724m5a.171009.epkg.Z | key_w_fix |
| 7.2.0.5 | IV94724m5a.171009.epkg.Z | key_w_fix |
| 7.2.1.1 | IV94723m3a.171009.epkg.Z | key_w_fix |
| 7.2.1.2 | IV94723m3a.171009.epkg.Z | key_w_fix |
| 7.2.1.3 | IV94723m3a.171009.epkg.Z | key_w_fix |

Please note that the above tables refer to AIX TL/SP level as
opposed to fileset level, i.e., 7.1.3.8 is AIX 7100-03-08.
                      
| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.5.20 | IV94728mAa.171008.epkg.Z | key_w_fix |
| 2.2.6.0 | IV94728mAa.171008.epkg.Z | key_w_fix  |
| 2.2.6.10 | IV94728mAa.171008.epkg.Z | key_w_fix |

The above fixes are cumulative and address previously issued
AIX tcpdump security bulletins with respect to SP and TL.

To extract the fixes from the tar file:

```
        tar xvf tcpdump_fix3.tar
        cd tcpdump_fix3
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the ```openssl dgst -sha256 [filename]``` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 6248b20c3af88225f6be5bd84f2ff3a901a8db300609dbd11e652a0d1fd831a5 | IV94723m3a.171009.epkg.Z | key_w_csum |
| a52bba4e3411a861e52f11cc961cc7a79be4f3359c56b256bad0888eb77309eb | IV94724m5a.171009.epkg.Z | key_w_csum |
| 178f356ad65b89b2584397506851a29af4ba5d280f51f7483e9d9ecfb6f01d7a | IV94726m5a.171009.epkg.Z | key_w_csum |
| 1d8cb7ecd0dd3f167860b4db7eab3a2b349e787b4f23858f02cd31bfab8278fa | IV94727m9a.171009.epkg.Z | key_w_csum |
| c1fff8799746a5d2eac51de70c51ef414f536c1bc7cd68174b087ba4e14cb59b | IV94728mAa.171008.epkg.Z | key_w_csum |
| d03367a2507bb0bb2ddb358b15ccc8303c5b7a0cb170f4b08dccb12246e4122f | IV94729m9a.171009.epkg.Z | key_w_csum |

         
These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM AIX Support at https://ibm.com/support/
and describe the discrepancy.

```
        openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]

        openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
``` 

Published advisory OpenSSL signature file location:

* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory3.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory3.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory3.asc.sig>

### B. INTERIM FIX INSTALLATION

IMPORTANT: If possible, it is recommended that a mksysb backup
of the system be created.  Verify it is both bootable and
readable before proceeding.

To preview a fix installation:

```
        installp -a -d fix_name -p all  # where fix_name is the name of the
                                        # fix package being previewed.
```
  
To install a fix package:

```
        installp -a -d fix_name -X all  # where fix_name is the name of the
                                        # fix package being installed.
```

Interim fixes have had limited functional and regression
testing but not the full regression testing that takes place
for Service Packs; however, IBM does fully support them.

Interim fix management documentation can be found at:
<http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html>

To preview an interim fix installation:

```
        emgr -e ipkg_name -p         # where ipkg_name is the name of the
                                     # interim fix package being previewed.
```

To install an interim fix package:
 
```
        emgr -e ipkg_name -X         # where ipkg_name is the name of the
                                     # interim fix package being installed.
```

### C. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | SP | KEY |
| --------- | ---- | -- | --- |
| 5.3.12 | IJ00568 | N/A | key_w_apar |
| 6.1.9 | IJ00563 | SP11 | key_w_apar |
| 7.1.3 | IJ00564 | N/A | key_w_apar |
| 7.1.4 | IJ00565 | SP6 | key_w_apar |
| 7.2.0 | IJ00566 | SP6 | key_w_apar |
| 7.2.1 | IJ00567 | SP4 | key_w_apar |

Please refer to AIX support lifecycle information page for availability
of Service Packs:
<http://www-01.ibm.com/support/docview.wss?uid=isg3T1012517>

Subscribe to the APARs here:

* https://www.ibm.com/support/docview.wss?uid=isg1IJ00568
* https://www.ibm.com/support/docview.wss?uid=isg1IJ00563
* https://www.ibm.com/support/docview.wss?uid=isg1IJ00564
* https://www.ibm.com/support/docview.wss?uid=isg1IJ00565
* https://www.ibm.com/support/docview.wss?uid=isg1IJ00566
* https://www.ibm.com/support/docview.wss?uid=isg1IJ00567
                 
By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.


## III. WORKAROUNDS AND MITIGATIONS

None.


## IV.VULNERABILITY DETAILS

Vulnerabilities in tcpdump affect AIX:

### CVEID: CVE-2017-12993 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12993
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12993
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the Juniper
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131892  for the  current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12992 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12992
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12992
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the RIPng
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131891  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12991 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12991
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12991
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the BGP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131886  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12988 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12988
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12988
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the telnet
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131885  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12987 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12987
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12987
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IEEE 802.11
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131883  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12986 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12986 
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12986
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6 routing
  headers component. By sending a specially crafted request, an
  attacker could exploit this vulnerability to obtain sensitive
  information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131876  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12985 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12985
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12985
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131875  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12902 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12902
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12902
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the Zephyr
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131874  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12901 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12901
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12901
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the EIGRP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131873  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12900 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12900
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12900
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the tok2strbuf
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131872  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12899 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12899
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12899
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the DECnet
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131871  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12898 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12898
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12898
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the NFS component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131868  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12897 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12897
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12897
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO CLNS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131867  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12896 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12896
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12896
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISAKMP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131877  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12895 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12895
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12895
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ICMP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131865  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12894 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12894
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12894
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the
  lookup_bytestring component. By sending a specially crafted request,
  an attacker could exploit this vulnerability to obtain sensitive
  information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131864  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12893 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12893
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12893
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the SMB/CIFS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131810  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-11542 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11542
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11542
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by a
  heap-based buffer over-read in the pimv1_print function in
  print-pim.c. An attacker could exploit this vulnerability to cause
  the application to crash. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/129253  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-11541 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11541
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11541
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by a
  heap-based buffer over-read in the lldp_print function in
  print-lldp.c. An attacker could exploit this vulnerability to cause
  the application to crash. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/129252  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-12997 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12997
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12997
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by an
  error in the LLDP component. By sending specially crafted data, a
  remote attacker could exploit this vulnerability to cause the
  application to enter into an infinite loop. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131809  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-12995 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12995
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12995
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by an
  error in the DNS component. By sending specially crafted data, a
  remote attacker could exploit this vulnerability to cause the
  application to enter into an infinite loop. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131808  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-12990 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12990
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12990
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by an
  error in the ISAKMP component. By sending specially crafted data, a
  remote attacker could exploit this vulnerability to cause the
  application to enter into an infinite loop. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131807  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-12989 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12989
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12989
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by an
  error in the RESP component. By sending specially crafted data, a
  remote attacker could exploit this vulnerability to cause the
  application to enter into an infinite loop. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131794  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-13011 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13011
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13011
* DESCRIPTION: tcpdump is vulnerable to a buffer overflow, caused by
  improper bounds checking by the bittok2str_internal component. By
  sending an overly long string argument, a remote attacker could
  overflow a buffer and execute arbitrary code on the system or cause
  the application to crash. 
* CVSS Base Score: 7.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131781  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L)

### CVEID: CVE-2017-11543 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11543
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11543
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by a
  buffer overflow in the sliplink_print function in print-sl.c. An
  attacker could exploit this vulnerability to cause the application
  to crash. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/129254  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-13018 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13018
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13018
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the PGM component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131912  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13017 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13017
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13017
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the DHCPv6
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131911  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13016 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13016
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13016
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO ES-IS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131909  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-11543 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11543
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11543
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by a
  buffer overflow in the sliplink_print function in print-sl.c. An
  attacker could exploit this vulnerability to cause the application
  to crash. 
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/129254  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-13015 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13015
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13015
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the EAP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131908  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13014 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13014
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13014
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the White Board
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131907  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13013 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13013
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13013
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ARP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131906  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13012 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13012
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13012
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ICMP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131878  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13010 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13010
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13010
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the BEEP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131905  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13009 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13009
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13009
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6 mobility
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131879  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13008 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13008
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13008
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IEEE 802.11
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131884  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13006 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13006
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13006
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the L2TP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131903  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13005 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13005
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13005
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the NFS component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131869  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13004 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13004
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13004
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the Juniper
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131893  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13003 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13003
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13003
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the LMP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131902  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13002 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13002
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13002
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the AODV
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131901  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13001 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13001
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13001
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the NFS component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131870  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13000 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13000
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13000
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IEEE 802.15.4
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131900  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12999 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12999
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12999
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO IS-IS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131896  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12998 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12998
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12998
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO IS-IS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131895  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12996 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12996
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12996
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the PIMv2
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131894  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-12994 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12994
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12994
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the BGP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131887  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-11541 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11541
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11541
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by a
  heap-based buffer over-read in the lldp_print function in
  print-lldp.c. An attacker could exploit this vulnerability to cause
  the application to crash.
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/129252  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-11542 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11542
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11542
* DESCRIPTION: tcpdump is vulnerable to a denial of service, caused by a
  heap-based buffer over-read in the pimv1_print function in
  print-pim.c. An attacker could exploit this vulnerability to cause
  the application to crash.
* CVSS Base Score: 7.5 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/129253  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### CVEID: CVE-2017-13043 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13043
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13043
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the BGP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131890  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13042 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13042
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13042
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the HNCP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132002  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13041 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13041
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13041
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ICMPv6
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131985  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13040 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13040
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13040
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the MPTCP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132001  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13039 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13039
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13039
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISAKMP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131866  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13038 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13038
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13038
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the PPP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132000  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13037 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13037
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13037
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131999  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13036 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13036
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13036
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the OSPFv3
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131998  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13035 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13035
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13035
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO IS-IS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131899  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13034 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13034
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13034
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the PGM component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131914  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13033 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13033
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13033
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the VTP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131983  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13032 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13032
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13032
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the RADIUS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131997  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13031 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13031
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13031
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6
  fragmentation header component. By sending a specially crafted
  request, an attacker could exploit this vulnerability to obtain
  sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131996  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13030 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13030
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13030
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the PIM component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131991  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13029 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13029
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13029
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the PPP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131990  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13028 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13028
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13028
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the BOOTP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131989  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13027 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13027
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13027
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the LLDP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131987  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13026 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13026
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13026
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO IS-IS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131897  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13025 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13025
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13025
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6 mobility
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131882  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13024 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13024
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13024
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6 mobility
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131881  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13023 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13023
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13023
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6 mobility
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131880  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

* ### CVEID: CVE-2017-13022 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13022
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13022
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131986  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13021 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13021
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13021
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ICMPv6
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131984  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13020 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13020
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13020
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the VTP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131982  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13019 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13019
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13019
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the PGM component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131913  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13725 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13725
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13725
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IPv6 routing
  headers component. By sending a specially crafted request, an
  attacker could exploit this vulnerability to obtain sensitive
  information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132014  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13690 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13690
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13690
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IKEv2
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132013  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13689 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13689
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13689
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the IKEv1
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132012  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13688 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13688
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13688
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the OLSR
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132011  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13687 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13687
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13687
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the Cisco HDLC
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132010  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13055 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13055
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13055
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO IS-IS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131898  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13054
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13054
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13054
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the LLDP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131988  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13053
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13053
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13053
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the BGP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131888  for the current score 
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13052
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13052
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13052
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the CFM component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132009  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13051
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13051
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13051
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the RSVP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132006  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13050
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13050
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13050
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the RPKI-Router
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132008  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13049
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13049
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13049
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the Rx component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132007  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13048
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13048
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13048
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the RSVP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132005  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13047
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13047
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13047
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the ISO ES-IS
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131910  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13046
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13046
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13046
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the BGP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/131889  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13045
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13045
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13045
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the VQP component.
  By sending a specially crafted request, an attacker could exploit
  this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132004  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

### CVEID: CVE-2017-13044
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13044
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13044
* DESCRIPTION: tcpdump could allow a remote attacker to obtain sensitive
  information, caused by a buffer overread memory in the HNCP
  component. By sending a specially crafted request, an attacker could
  exploit this vulnerability to obtain sensitive information.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/132003  for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing purposes.

If you would like to receive AIX Security Advisories via email,
please visit "My Notifications":

* <http://www.ibm.com/support/mynotifications>
* <https://www.ibm.com/support/mynotifications>

To view previously issued advisories, please visit:

* <http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>
* <https://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>
   
To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page: 
* <http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt>
* <https://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

# REFERENCES
 
* Complete CVSS v3 Guide:
  <http://www.first.org/cvss/user-guide>
  <https://www.first.org/cvss/user-guide>
* On-line Calculator v3:
  <http://www.first.org/cvss/calculator/3.0>
  <https://www.first.org/cvss/calculator/3.0>

# ACKNOWLEDGEMENTS

None 

# CHANGE HISTORY

* First Issued: Wed Nov  8 09:27:01 CST 2017 
* Updated: Wed Feb 28 09:33:13 CST 2018 
* Update: Corrected the APARs listed under the APAR section.

===============================================================================

The CVSS Environment Score is customer environment specific and will 
ultimately impact the Overall CVSS Score. Customers can evaluate the impact 
of this vulnerability in their environments by accessing the links in the 
Reference section of this Security Bulletin. 

Disclaimer

According to the Forum of Incident Response and Security Teams (FIRST), the 
Common Vulnerability Scoring System (CVSS) is an "industry open standard 
designed to convey vulnerability severity and help to determine urgency and 
priority of response." IBM PROVIDES THE CVSS SCORES "AS IS" WITHOUT WARRANTY 
OF ANY KIND, INCLUDING THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE. CUSTOMERS ARE RESPONSIBLE FOR ASSESSING THE IMPACT 
OF ANY ACTUAL OR POTENTIAL SECURITY VULNERABILITY.
 




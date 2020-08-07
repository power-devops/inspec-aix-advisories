# IBM SECURITY ADVISORY

First Issued: Mon Feb 25 16:54:49 CST 2019

Updated: Wed Mar  6 16:31:00 CST 2019

Update: Additional AIX iFixes now available.

Updated: Tue Apr  9 09:55:34 CDT 2019

Update: Increased the lower impacted fileset levels for some fileset 
levels. Please see the Fileset table in AFFECTED PRODUCTS AND VERSIONS 
for more information.


The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory4.asc>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory4.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory4.asc>

Security Bulletin: Vulnerability in tcpdump affects AIX (CVE-2018-19519)

# SUMMARY

There is a vulnerability in tcpdump that affects AIX.

# VULNERABILITY DETAILS

* CVEID: CVE-2018-19519
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19519>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19519>
* *DESCRIPTION* 
  Tcpdump is vulnerable to a stack-based buffer overflow, 
  caused by improper bounds checking by the print_prefix function of 
  print-hncp.c. By using a specially-crafted packet data, a remote 
  attacker could overflow a buffer and execute arbitrary code on the 
  system or cause the application to crash.
* CVSS Base Score: 7.3
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/153314> for the current score
* CVSS Environmental Score Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L)


# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX 6.1, 7.1, 7.2
* VIOS 2.2.x 

The following fileset levels are vulnerable:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.server | 6.1.9.300 | 6.1.9.400 | key_w_fs |
| bos.net.tcp.server | 7.1.4.32 | 7.1.4.34 | key_w_fs |
| bos.net.tcp.server | 7.1.5.0 | 7.1.5.31 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.1.1 | 7.2.1.3 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.2.0 | 7.2.2.16 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.3.0 | 7.2.3.15 | key_w_fs |

To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

```
  lslpp -L | grep -i bos.net.tcp.server
```


# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 7.1.4 | IJ12979 | ** | SP08-1914 | key_w_apar | 
| 7.1.5 | IJ12980 | ** | SP04-1913 | key_w_apar |
| 7.2.1 | IJ12981 | ** | SP06-1914 | key_w_apar |
| 7.2.2 | IJ12982 | ** | SP04-1914 | key_w_apar |
| 7.2.3 | IJ12983 | ** | SP03-1913 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.5 | IJ12978 | ** | 2.2.5.60 | key_w_apar | 
| 2.2.6 | IJ12978 | ** | 2.2.6.40 | key_w_apar |
| 3.1.0 | IJ12983 | ** | 3.1.0.20 | key_w_apar |

Subscribe to the APARs here:

* <http://www.ibm.com/support/docview.wss?uid=isg1IJ12978>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ12979>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ12980>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ12981>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ12982>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ12983>

* <https://www.ibm.com/support/docview.wss?uid=isg1IJ12978>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ12979>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ12980>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ12981>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ12982>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ12983>

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX and VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_fix4.tar>
* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_fix4.tar>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_fix4.tar> 

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 7.1.4.5 | IJ12979m5a.190304.epkg.Z | key_w_fix |
| 7.1.4.6 | IJ12979m6a.190304.epkg.Z | key_w_fix |
| 7.1.4.7 | IJ12979m7a.190205.epkg.Z | key_w_fix |
| 7.1.5.1 | IJ12980m1a.190207.epkg.Z | key_w_fix |
| 7.1.5.2 | IJ12980m2a.190212.epkg.Z | key_w_fix |
| 7.1.5.3 | IJ12980m3a.190212.epkg.Z | key_w_fix |
| 7.2.1.3 | IJ12981m3a.190214.epkg.Z | key_w_fix |
| 7.2.1.4 | IJ12981m4a.190215.epkg.Z | key_w_fix |
| 7.2.1.5 | IJ12981m5a.190225.epkg.Z | key_w_fix |
| 7.2.2.1 | IJ12982m1a.190215.epkg.Z | key_w_fix |
| 7.2.2.2 | IJ12982m2a.190215.epkg.Z | key_w_fix |
| 7.2.2.3 | IJ12982m3a.190215.epkg.Z | key_w_fix |
| 7.2.3.0 | IJ12983m0a.190215.epkg.Z | key_w_fix |
| 7.2.3.1 | IJ12983m1a.190215.epkg.Z | key_w_fix |
| 7.2.3.2 | IJ12983m2a.190215.epkg.Z | key_w_fix |
    
Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.3 is AIX 7200-02-03.

Please reference the Affected Products and Version section above
for help with checking installed fileset levels.

| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.5.40 | IJ12978s9a.190215.epkg.Z | key_w_fix |
| 2.2.5.50 | IJ12978s9a.190215.epkg.Z | key_w_fix |
| 2.2.6.21 | IJ12978sBa.190215.epkg.Z | key_w_fix |
| 2.2.6.23 | IJ12978sBa.190215.epkg.Z | key_w_fix |
| 2.2.6.32 | IJ12978sCa.190215.epkg.Z | key_w_fix |
| 3.1.0.10 | IJ12983m2a.190215.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
  tar xvf tcpdump_fix4.tar
  cd tcpdump_fix4
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the
`openssl dgst -sha256 [filename]` command as the following:

| openssl dgst -sha256 | filename | KEY | 
| -------------------- | -------- | --- |
| 2e05ddb65cb649d7c68342573823c7aca9febbf55ac4e4b761c6cc3429f9c472 | IJ12978s9a.190215.epkg.Z | key_w_csum |
| 819ab2731f480d654db43159adf92176726edbc9377769e0215461713c933714 | IJ12978sBa.190215.epkg.Z | key_w_csum |
| 216fc77d43f0713873ccb0cc7b5f531216245e4eefc02ca07b56b763ddf0c5da | IJ12978sCa.190215.epkg.Z | key_w_csum |
| 8a8c3ba84781f2b0f007ac93568a629be5bd65119b7b76a75f4c80496f8193ed | IJ12979m5a.190304.epkg.Z | key_w_csum |
| a8f82929828046dabbfe0f22b998026878254b31948e943ba7487d8b12ab598b | IJ12979m6a.190304.epkg.Z | key_w_csum |
| 959cc124a81763c57bd1c9576f8c180a581f7685a9b6ee17e517f9863dc5f7c7 | IJ12979m7a.190205.epkg.Z | key_w_csum |
| 50eb9a6281393c0f4464c54e984fc66cb3be0ed931b2e828b6ca9a38c5477b03 | IJ12980m1a.190207.epkg.Z | key_w_csum |
| 5d8fba67e88068dba76fbd7dd6ee4fc8d01de2e4c1b5fd99ce672624ab62b2bc | IJ12980m2a.190212.epkg.Z | key_w_csum |
| 0c0790166da0f92f198abfe50255a9282c458a8f3f8158b17660512e67de8003 | IJ12980m3a.190212.epkg.Z | key_w_csum |
| 1d25c5255cf39f872e516e2e312894bf9677e6d1062a74ba5b792425647032c7 | IJ12981m3a.190214.epkg.Z | key_w_csum |
| a2932c10a0755981827ef6f105e5d393c29a91766de28e99a442f3845f505227 | IJ12981m4a.190215.epkg.Z | key_w_csum |
| cae215ce40cf9bd51f4fbbdee172258a1b24143cf1004e30b102416b359a4a87 | IJ12981m5a.190225.epkg.Z | key_w_csum |
| 2f94de4c9d3fc3aaf55aa923fb8cc25054b436d28b03a8e145f2197d74938e95 | IJ12982m1a.190215.epkg.Z | key_w_csum |
| 5ea43c493fdeb5889a58a138b7050de20e6ef776a39c2def0fc06c58bc227940 | IJ12982m2a.190215.epkg.Z | key_w_csum |
| 1a8bbeed0a375739b133c317099ab938a43f670a355fd76f16641a640c7039d3 | IJ12982m3a.190215.epkg.Z | key_w_csum |
| b1d3979a1e9a5c1ed90a15d24974ba80430573e0ae61ee967d4c7304bdef8c94 | IJ12983m0a.190215.epkg.Z | key_w_csum |
| 1e48107063297522366390de5eb1648a1d98edbaf3092bddf8aecec6ce45af6b | IJ12983m1a.190215.epkg.Z | key_w_csum |
| b87249e90504d241f9359c66f16527e2cd73c1b50a05199d4968ad5a79f10af7 | IJ12983m2a.190215.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at
http://ibm.com/support/ and describe the discrepancy.         
 
```
  openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
 
  openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory4.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory4.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory4.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

If possible, it is recommended that a mksysb backup of the system 
be created. Verify it is both bootable and readable before
proceeding.

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

* <http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html>

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

# WORKAROUNDS AND MITIGATIONS

None.


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing
purposes.

If you would like to receive AIX Security Advisories via email,
please visit "My Notifications":

* <http://www.ibm.com/support/mynotifications>

To view previously issued advisories, please visit:

* <http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>
 
Contact IBM Support for questions related to this announcement:

* <http://ibm.com/support/>
* <https://ibm.com/support/>

To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page:

* <ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.


# REFERENCES
 
Complete CVSS v3 Guide:  <http://www.first.org/cvss/user-guide>

On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>

IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>

Security Bulletin: Vulnerability in tcpdump affects AIX (CVE-2018-19519) <https://www-01.ibm.com/support/docview.wss?uid=ibm10873086>


# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Mon Feb 25 16:54:49 CST 2019

Updated: Wed Mar  6 16:31:00 CST 2019

Update: Additional AIX iFixes now available.

Updated: Tue Apr  9 09:55:34 CDT 2019

Update: Increased the lower impacted fileset levels for some fileset 
levels. Please see the Fileset table in AFFECTED PRODUCTS AND VERSIONS
for more information.

The CVSS Environment Score is customer environment specific and will 
ultimately impact the Overall CVSS Score. Customers can evaluate the impact 
of this vulnerability in their environments by accessing the links in the 
Reference section of this Security Bulletin. 

*Disclaimer*

According to the Forum of Incident Response and Security Teams (FIRST), the 
Common Vulnerability Scoring System (CVSS) is an "industry open standard 
designed to convey vulnerability severity and help to determine urgency and 
priority of response." IBM PROVIDES THE CVSS SCORES "AS IS" WITHOUT WARRANTY 
OF ANY KIND, INCLUDING THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE. CUSTOMERS ARE RESPONSIBLE FOR ASSESSING THE IMPACT 
OF ANY ACTUAL OR POTENTIAL SECURITY VULNERABILITY.






# IBM SECURITY ADVISORY

First Issued: Tue Aug 14 14:48:57 CDT 2018

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/ntp_advisory10.asc>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_advisory10.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_advisory10.asc>

Security Bulletin: Vulnerabilities in NTP affect AIX

# SUMMARY

There are multiple vulnerabilities in NTPv3 and NTPv4 that affect AIX.

# VULNERABILITY DETAILS

NTPv3 is vulnerable to:

## CVEID: CVE-2014-5209
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5209>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5209>
* *DESCRIPTION* 
  NTP could allow a remote attacker to obtain sensitive 
  information. By sending a GET_RESTRICT control message, an attacker 
  could exploit this vulnerability to obtain internal or alternative 
  IP addresses and other sensitive information.
* CVSS Base Score: 5.0
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/95841 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (AV:N/AC:L/Au:N/C:P/I:N/A:N)

NTPv3 and NTPv4 are vulnerable to:

## CVEID: CVE-2018-7182
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7182>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7182>
* *DESCRIPTION*
  NTP could allow a remote attacker to obtain sensitive 
  information, caused by a leak in the ctl_getitem() function. By 
  sending a specially crafted mode 6 packet, an attacker could exploit 
  this vulnerability to read past the end of its buffer.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/139785 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

## CVEID: CVE-2018-7183
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7183>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7183>
* *DESCRIPTION*
  NTP is vulnerable to a buffer overflow, caused by improper 
  bounds checking by the decodearr function. By leveraging an ntpq 
  query and sending a response with a crafted array, a remote attacker 
  could overflow a buffer and execute arbitrary code on the system or 
  cause the application to crash.
* CVSS Base Score: 5.6
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/140092 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L)

NTPv4 is vulnerable to:

## CVEID: CVE-2018-7170
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7170>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7170>
* *DESCRIPTION* 
  NTP could allow a remote authenticated attacker to bypass 
  security restrictions, caused by a Sybil attack. By creating many 
  ephemeral associations, an attacker could exploit this vulnerability 
  to win the clock selection of ntpd and modify a victim's clock. 
* CVSS Base Score: 3.1
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/139786 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N)

## CVEID: CVE-2018-7184
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7184>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7184>
* *DESCRIPTION* 
  NTP is vulnerable to a denial of service, caused by the 
  failure of the interleaved symmetric mode to recover from bad state. 
  By sending specially crafted packets, a remote authenticated 
  attacker could exploit this vulnerability to cause a denial of 
  service.
* CVSS Base Score: 3.1
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/139784 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L)

## CVEID: CVE-2018-7185
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7185>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7185>
* *DESCRIPTION*
  NTP is vulnerable to a denial of service. By sending 
  specially crafted packets, a remote authenticated attacker could 
  exploit this vulnerability to reset authenticated interleaved 
  association.
* CVSS Base Score: 3.1
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/139783 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L)

## CVEID: CVE-2016-1549
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1549>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1549>
* *DESCRIPTION* 
  NTP could allow a remote authenticated attacker to 
  bypass security restrictions, caused by the failure to prevent 
  Sybil attacks from authenticated peers. By creating multiple 
  ephemeral associations to win the clock selection of ntpd, an 
  attacker could exploit this vulnerability to modify a victim's 
  clock.
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/112741 for the current score 
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N)


# AFFECTED PRODUCTS AND VERSIONS
 
* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x 

The vulnerabilities in the following filesets are being addressed:
        
key_fileset = aix

For NTPv3:

| Fileset | Lower Level | Upper Level | KEY | PRODUCT(S) |
| ------- | ----------- | ----------- | --- | ---------- |
| bos.net.tcp.client | 5.3.12.0 | 5.3.12.10 | key_w_fs | NTPv3 |
| bos.net.tcp.client | 6.1.9.0 | 6.1.9.315 | key_w_fs | NTPv3 |
| bos.net.tcp.client | 7.1.4.0 | 7.1.4.33 | key_w_fs | NTPv3 |
| bos.net.tcp.client | 7.1.5.0 | 7.1.5.15 | key_w_fs | NTPv3 |
| bos.net.tcp.ntpd | 7.2.0.0 | 7.2.0.4 | key_w_fs | NTPv3 | 
| bos.net.tcp.ntpd | 7.2.1.0 | 7.2.1.2 | key_w_fs | NTPv3 |
| bos.net.tcp.ntpd | 7.2.2.0 | 7.2.2.15 | key_w_fs | NTPv3 |

For NTPv4:

| Fileset | Lower Level | Upper Level | KEY | PRODUCT(S) |
| ------- | ----------- | ----------- | --- | ---------- |
| ntp.rte | 7.4.2.8100 | 7.4.2.8100 | key_w_fs | NTPv4 |

To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

    lslpp -L | grep -i bos.net.tcp.client


# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

For NTPv3:

| AIX Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| --------- | ---- | ------------ | -- | --- | ---------- |
| 5.3.12 | IJ06657 | ** | N/A | key_w_apar | NTPv3 |
| 6.1.9 | IJ06651 | ** | SP12 | key_w_apar | NTPv3 |
| 7.1.4 | IJ06652 | ** | SP7 | key_w_apar | NTPv3 |
| 7.1.5 | IJ06653 | ** | SP3 | key_w_apar | NTPv3 |
| 7.2.0 | IJ06654 | ** | N/A | key_w_apar | NTPv3 |
| 7.2.1 | IJ06655 | ** | SP5 | key_w_apar | NTPv3 |
| 7.2.2 | IJ06656 | ** | SP3 | key_w_apar | NTPv3 |

| VIOS Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| ---------- | ---- | ------------ | -- | --- | ---------- |
| 2.2.4 | IJ06651 | ** | N/A | key_w_apar | NTPv3 |
| 2.2.5 | IJ06651 | ** | 2.2.5.50 | key_w_apar | NTPv3 |
| 2.2.6 | IJ06651 | ** | 2.2.6.30 | key_w_apar | NTPv3 |

For NTPv4:

| AIX Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| --------- | ---- | ------------ | -- | --- | ---------- |
| 6.1.9 | IJ06400 | ** | SP12 | key_w_apar | NTPv4 |
| 7.1.4 | IJ06400 | ** | SP7 | key_w_apar | NTPv4 |
| 7.1.5 | IJ06400 | ** | SP3 | key_w_apar | NTPv4 |
| 7.2.0 | IJ06400 | ** | N/A | key_w_apar | NTPv4 |
| 7.2.1 | IJ06400 | ** | SP5 | key_w_apar | NTPv4 |
| 7.2.2 | IJ06400 | ** | SP3 | key_w_apar | NTPv4 |

| VIOS Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| ---------- | ---- | ------------ | -- | --- | ---------- |
| 2.2.4 | IJ06400 | ** | N/A | key_w_apar | NTPv4 |
| 2.2.5 | IJ06400 | ** | 2.2.5.50 | key_w_apar | NTPv4 |
| 2.2.6 | IJ06400 | ** | 2.2.6.30 | key_w_apar | NTPv4 |

Subscribe to the APARs here:

* http://www.ibm.com/support/docview.wss?uid=isg1IJ06400
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06651
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06652
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06653
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06654
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06655
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06656

* https://www.ibm.com/support/docview.wss?uid=isg1IJ06400
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06651
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06652
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06653
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06654
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06655
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06656

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX/VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_fix10.tar>
* <http://aix.software.ibm.com/aix/efixes/security/ntp_fix10.tar>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_fix10.tar>

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.
           
For NTPv3:
 
| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 5.3.12.9 | IJ06657m9a.180529.epkg.Z | key_w_fix | NTPv3 |
| 6.1.9.9 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3 |
| 6.1.9.10 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3 |
| 6.1.9.11 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3 |
| 7.1.4.4 | IJ06652m4a.180528.epkg.Z | key_w_fix | NTPv3 |
| 7.1.4.5 | IJ06652m4a.180528.epkg.Z | key_w_fix | NTPv3 |
| 7.1.4.6 | IJ06652m4a.180528.epkg.Z | key_w_fix | NTPv3 |
| 7.1.5.0 | IJ06653m0a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.1.5.1 | IJ06653m0a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.1.5.2 | IJ06653m0a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.0.4 | IJ06654m4a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.0.5 | IJ06654m4a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.0.6 | IJ06654m4a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.1.2 | IJ06655m2a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.1.3 | IJ06655m2a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.1.4 | IJ06655m2a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.2.0 | IJ06656m0a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.2.1 | IJ06656m0a.180527.epkg.Z | key_w_fix | NTPv3 |
| 7.2.2.2 | IJ06656m0a.180527.epkg.Z | key_w_fix | NTPv3 |

Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.2 is AIX 7200-02-02.


| VIOS Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| ---------- | ----------------- | --- | ---------- |
| 2.2.4.40 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.4.50 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.4.60 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.5.20 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.5.30 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.5.40 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.6.0 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.6.10 | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3
| 2.2.6.2x | IJ06651m9a.180528.epkg.Z | key_w_fix | NTPv3


For NTPv4:


| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 6.1.x | IJ06400s9a.180514.epkg.Z | key_w_fix | NTPv4 |
| 7.1.x | IJ06400s9a.180514.epkg.Z | key_w_fix | NTPv4 |
| 7.2.x | IJ06400s9a.180514.epkg.Z | key_w_fix | NTPv4 |

| VIOS Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| ---------- | ----------------- | --- | ---------- |
| 2.2.x | IJ06400s9a.180514.epkg.Z | key_w_fix | NTPv4 |

To extract the fixes from the tar file:

```
    tar xvf ntp_fix10.tar 
    cd ntp_fix10
``` 

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 file` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 456eefb0975171e71cedd71431b6e23ebf16b226c4344a34b9c6452cb862fc42 | IJ06400s9a.180514.epkg.Z | key_w_csum |
| e17cc1dc210f3b8f802d4b52cda05f1a89cd6de2cea371e9a7bea5452dd686f5 | IJ06651m9a.180528.epkg.Z | key_w_csum |
| 3c92a6063d36be79cd716843fc8221f96911922a62b91a20e86d10ead054255a | IJ06652m4a.180528.epkg.Z | key_w_csum |
| 17f7a37fedba73dd7e3862ced003436b22c5b74c7ca8dcc0dcde3306cff0d64f | IJ06653m0a.180527.epkg.Z | key_w_csum |
| 7792b56540634644b2fb9b47a8d5449eb62a89ea83e965e265d5b3fe3a2d01bd | IJ06654m4a.180527.epkg.Z | key_w_csum |
| 223874b300b8a4201c6f6cdc0eb53bc09e4c22f9f00902713143b3df3569e0c0 | IJ06655m2a.180527.epkg.Z | key_w_csum |
| f0e0c59274a89dc18064f8e49d4fa47de870e94b3b2d84d841f2e41c890cd035 | IJ06656m0a.180527.epkg.Z | key_w_csum |
| 4a8e6ba8e5f5bf6651c339ee8ccffbcf6cd50f5004f1598d0ac70ecfe58ee823 | IJ06657m9a.180529.epkg.Z | key_w_csum |

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
 
* <http://aix.software.ibm.com/aix/efixes/security/ntp_advisory10.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_advisory10.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_advisory10.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

If possible, it is recommended that a mksysb backup of the system 
be created. Verify it is both bootable and readable before
proceeding.

The fix will not take affect until any running xntpd servers
have been stopped and restarted with the  following commands:

```
    stopsrc -s xntpd
    startsrc -s xntpd
```

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

After installation the ntp daemon must be restarted:

```
                stopsrc -s xntpd
                startsrc -s xntpd
```

Interim fixes have had limited functional and regression
testing but not the full regression testing that takes place
for Service Packs; however, IBM does fully support them.

Interim fix management documentation can be found at:

http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html

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

Note: Keywords labeled as KEY in this document are used for parsing purposes.

If you would like to receive AIX Security Advisories via email, please visit "My Notifications":

* http://www.ibm.com/support/mynotifications

To view previously issued advisories, please visit:

* http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq
 
Contact IBM Support for questions related to this announcement:

* http://ibm.com/support/
* https://ibm.com/support/

To obtain the OpenSSL public key that can be used to verify the signed advisories and ifixes:

Download the key from our web page:

* <ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.


# REFERENCES
 
* Complete CVSS v3 Guide:  http://www.first.org/cvss/user-guide
* On-line Calculator v3: http://www.first.org/cvss/calculator/3.0


# RELATED INFORMATION

* IBM Secure Engineering Web Portal http://www.ibm.com/security/secure-engineering/bulletins.html

* IBM Product Security Incident Response Blog https://www.ibm.com/blogs/psirt/

* Security Bulletin: Vulnerabilities in NTP affect AIX https://www-01.ibm.com/support/docview.wss?uid=ibm10718835

# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Tue Aug 14 14:48:57 CDT 2018


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






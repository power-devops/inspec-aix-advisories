# IBM SECURITY ADVISORY

First Issued: Mon Aug 19 16:44:22 CDT 2019

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/ntp_advisory12.asc>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_advisory12.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_advisory12.asc>

Security Bulletin: Vulnerability in NTP affects AIX (CVE-2019-8936)

# SUMMARY

There is a vulnerability in NTPv3 and NTPv4 that affects AIX.

# VULNERABILITY DETAILS

NTPv3 and NTPv4 are vulnerable to:

## CVEID: CVE-2019-8936
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8936>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8936>
* *DESCRIPTION* NTP is vulnerable to a denial of service, caused by a NULL 
  pointer dereference in ntp_control.c. By sending specially crafted 
  mode 6 packets, a remote authenticated attacker could exploit this 
  vulnerability to cause the ntpd daemon to SIGSEGV.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/158926 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H)


# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX 7.1, 7.2
* VIOS 2.2, 3.1

The vulnerabilities in the following filesets are being addressed:
        
key_fileset = aix

For NTPv3:

| Fileset | Lower Level | Upper Level | KEY | PRODUCT(S) |
| ------- | ----------- | ----------- | --- | ---------- |
| bos.net.tcp.client | 6.1.9.0 | 6.1.9.404 | key_w_fs | NTPv3 |
| bos.net.tcp.client | 7.1.4.0 | 7.1.4.35 | key_w_fs | NTPv3 |
| bos.net.tcp.client | 7.1.5.0 | 7.1.5.33 | key_w_fs | NTPv3 |
| bos.net.tcp.ntp | 7.2.1.0 | 7.2.1.2 | key_w_fs | NTPv3 |
| bos.net.tcp.ntpd | 7.2.1.0 | 7.2.1.3 | key_w_fs | NTPv3 |
| bos.net.tcp.ntp | 7.2.2.0 | 7.2.2.17 | key_w_fs | NTPv3 |
| bos.net.tcp.ntpd | 7.2.2.0 | 7.2.2.17 | key_w_fs | NTPv3 |
| bos.net.tcp.ntp | 7.2.3.0 | 7.2.3.15 | key_w_fs | NTPv3 |
| bos.net.tcp.ntpd | 7.2.3.0 | 7.2.3.15 | key_w_fs | NTPv3 |

For NTPv4:

| Fileset | Lower Level | Upper Level | KEY | PRODUCT(S) |
| ------- | ----------- | ----------- | --- | ---------- |
| ntp.rte | 7.4.2.8100 | 7.4.2.8121 | key_w_fs | NTPv4 |

 
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

```
lslpp -L | grep -i bos.net.tcp.client
```

# REMEDIATION:

## A. APARS

IBM has assigned the following APARs to this problem:

For NTPv3:

| AIX Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| --------- | ---- | ------------ | -- | --- | ---------- |
| 7.1.4 | IJ17061 | ** | N/A | key_w_apar | NTPv3 |
| 7.1.5 | IJ17062 | ** | SP5 | key_w_apar | NTPv3 |
| 7.2.1 | IJ17063 | ** | N/A | key_w_apar | NTPv3 |
| 7.2.2 | IJ17064 | ** | SP5 | key_w_apar | NTPv3 |
| 7.2.3 | IJ17065 | ** | SP4 | key_w_apar | NTPv3 |

| VIOS Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| ---------- | ---- | ------------ | -- | --- | ---------- |
| 2.2.5 | IJ17060 | ** | N/A | key_w_apar | NTPv3 |
| 2.2.6 | IJ17060 | ** | 2.2.6.50 | key_w_apar | NTPv3 |
| 3.1.0 | IJ17065 | ** | 3.1.0.30 | key_w_apar | NTPv3 |

For NTPv4:

| AIX Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| --------- | ---- | ------------ | -- | --- | ---------- |
| 7.1.4 | IJ17059 | ** | N/A | key_w_apar | NTPv4 |
| 7.1.5 | IJ17059 | ** | SP5 | key_w_apar | NTPv4 |
| 7.2.1 | IJ17059 | ** | N/A | key_w_apar | NTPv4 |
| 7.2.2 | IJ17059 | ** | SP5 | key_w_apar | NTPv4 |
| 7.2.3 | IJ17059 | ** | SP4 | key_w_apar | NTPv4 |

| VIOS Level | APAR | Availability | SP | KEY | PRODUCT(S) |
| ---------- | ---- | ------------ | -- | --- | ---------- |
| 2.2.5 | IJ17059 | ** | N/A | key_w_apar | NTPv4 |
| 2.2.6 | IJ17059 | ** | 2.2.6.50 | key_w_apar | NTPv4 |
| 3.1.0 | IJ17059 | ** | 3.1.0.30 | key_w_apar | NTPv4 |

Subscribe to the APARs here:

* http://www.ibm.com/support/docview.wss?uid=isg1IJ17060
* http://www.ibm.com/support/docview.wss?uid=isg1IJ17061
* http://www.ibm.com/support/docview.wss?uid=isg1IJ17062
* http://www.ibm.com/support/docview.wss?uid=isg1IJ17063
* http://www.ibm.com/support/docview.wss?uid=isg1IJ17064
* http://www.ibm.com/support/docview.wss?uid=isg1IJ17065
* http://www.ibm.com/support/docview.wss?uid=isg1IJ17059

* https://www.ibm.com/support/docview.wss?uid=isg1IJ17060
* https://www.ibm.com/support/docview.wss?uid=isg1IJ17061
* https://www.ibm.com/support/docview.wss?uid=isg1IJ17062
* https://www.ibm.com/support/docview.wss?uid=isg1IJ17063
* https://www.ibm.com/support/docview.wss?uid=isg1IJ17064
* https://www.ibm.com/support/docview.wss?uid=isg1IJ17065
* https://www.ibm.com/support/docview.wss?uid=isg1IJ17059

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX/VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_fix12.tar>
* <http://aix.software.ibm.com/aix/efixes/security/ntp_fix12.tar>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_fix12.tar> 

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.
           
For NTPv3:
 
| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 7.1.4.6 | IJ17061m8a.190628.epkg.Z | key_w_fix | NTPv3 |
| 7.1.4.7 | IJ17061m8a.190628.epkg.Z | key_w_fix | NTPv3 |
| 7.1.4.8 | IJ17061m8a.190628.epkg.Z | key_w_fix | NTPv3 |
| 7.1.5.2 | IJ17062m4a.190628.epkg.Z | key_w_fix | NTPv3 |
| 7.1.5.3 | IJ17062m4a.190628.epkg.Z | key_w_fix | NTPv3 |
| 7.1.5.4 | IJ17062m4a.190628.epkg.Z | key_w_fix | NTPv3 |
| 7.2.1.4 | IJ17063m6a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.1.5 | IJ17063m6a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.1.6 | IJ17063m6a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.2.2 | IJ17064m4a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.2.3 | IJ17064m4a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.2.4 | IJ17064m4a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.3.1 | IJ17065m3a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.3.2 | IJ17065m3a.190701.epkg.Z | key_w_fix | NTPv3 |
| 7.2.3.3 | IJ17065m3a.190701.epkg.Z | key_w_fix | NTPv3 |

Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.2 is AIX 7200-02-02.


| VIOS Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| ---------- | ----------------- | --- | ---------- |
| 2.2.5.40 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.5.50 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.5.60 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.20 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.21 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.23 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.30 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.31 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.32 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.40 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 2.2.6.41 | IJ17060m9a.190628.epkg.Z | key_w_fix | NTPv3 |
| 3.1.0.0  | IJ17065m3a.190701.epkg.Z | key_w_fix | NTPv3 |
| 3.1.0.10 | IJ17065m3a.190701.epkg.Z | key_w_fix | NTPv3 |
| 3.1.0.20 | IJ17065m3a.190701.epkg.Z | key_w_fix | NTPv3 |
| 3.1.0.21 | IJ17065m3a.190701.epkg.Z | key_w_fix | NTPv3 |


For NTPv4:

| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 7.1.x | IJ17059m9b.190719.epkg.Z | key_w_fix | NTPv4 |
| 7.2.x | IJ17059m9b.190719.epkg.Z | key_w_fix | NTPv4 |

| VIOS Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| ---------- | ----------------- | --- | ---------- |
| 2.2.x | IJ17059m9b.190719.epkg.Z | key_w_fix | NTPv4 |
| 3.1.0.x | IJ17059m9b.190719.epkg.Z | key_w_fix | NTPv4 |

To extract the fixes from the tar file:

```
tar xvf ntp_fix12.tar 
cd ntp_fix12
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the ```openssl dgst -sha256 file``` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 5543f8cfe79e9b260b1ffd795f1e755d063564cb436e77b56ccf3c806378d2ca | IJ17059m9b.190719.epkg.Z | key_w_csum |
| fa9702b1406fd3b1437ac333f4a5a35cc8c8b6322a83970fbed6cf3f0ea73d5d | IJ17060m9a.190628.epkg.Z | key_w_csum |
| 6b15b60f21f0a6e9506373ac5178aaf6a11e12a54087b27120614641222d0c48 | IJ17061m8a.190628.epkg.Z | key_w_csum |
| 97e5c6ff951552e0b88a7ea61cf4b368844ae9d72721d923176f3c55b7340a0a | IJ17062m4a.190628.epkg.Z | key_w_csum |
| cd980f0e6ef7c69e5d1ad48eeb4bfc6f621a34747af28bf2c3e161e89fce251b | IJ17063m6a.190701.epkg.Z | key_w_csum |
| fa52c67254367424a611a269932b6de63c1d404ed9dd6cfa79eab465b91f11c6 | IJ17064m4a.190701.epkg.Z | key_w_csum |
| 71bfbe4fb5697bc18d5a5d5524c9d64f08040aea04de765d1c1183c532006ef7 | IJ17065m3a.190701.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at
http://ibm.com/support/ and describe the discrepancy.         
 
```
openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
```
 
```
openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/ntp_advisory12.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_advisory12.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_advisory12.asc.sig>

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

# WORKAROUNDS AND MITIGATIONS

None.


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing purposes.

If you would like to receive AIX Security Advisories via email, please visit "My Notifications":

<http://www.ibm.com/support/mynotifications>

To view previously issued advisories, please visit:

<http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>
 
Contact IBM Support for questions related to this announcement:

* <http://ibm.com/support/>
* <https://ibm.com/support/>

To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page:

<ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

# REFERENCES
 
* Complete CVSS v3 Guide:  http://www.first.org/cvss/user-guide
* On-line Calculator v3: http://www.first.org/cvss/calculator/3.0

# RELATED INFORMATION

IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>

IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>

Security Bulletin: Vulnerability in NTP affects AIX (CVE-2019-8936) <https://www-01.ibm.com/support/docview.wss?uid=ibm10961772>

# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Mon Aug 19 16:44:22 CDT 2019

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




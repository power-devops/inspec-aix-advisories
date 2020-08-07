# IBM SECURITY ADVISORY

First Issued: Fri Dec 14 12:20:13 CST 2018

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/ntp_advisory11.asc>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_advisory11.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_advisory11.asc>

Security Bulletin: Vulnerabilities in NTPv4 affect AIX (CVE-2018-12327, CVE-2018-7170)

# SUMMARY

There are vulnerabilities in NTPv4 that affect AIX.

# VULNERABILITY DETAILS

NTPv4 is vulnerable to:

## CVEID: CVE-2018-12327
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12327>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12327>
* *DESCRIPTION*
  NTP is vulnerable to a stack-based buffer overflow, caused 
  by improper bounds checking by ntpq and ntpdc. By sending an overly 
  long string argument, a local attacker could overflow a buffer and 
  execute arbitrary code on the system with elevated privileges or 
  cause the application to crash.
* CVSS Base Score: 5.9
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/145120 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L)

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

# AFFECTED PRODUCTS AND VERSIONS
 
* AIX 6.1, 7.1, 7.2
* VIOS 2.2.x 

The vulnerabilities in the following filesets are being addressed:
        
key_fileset = aix

For NTPv4:

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| ntp.rte | 7.4.2.8100 | 7.4.2.8110 | key_w_fs |

 
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

```
lslpp -L | grep -i ntp.rte
```


# REMEDIATION

## FIXES

AIX and VIOS fixes are available.

The AIX/VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_fix11.tar>
* <http://aix.software.ibm.com/aix/efixes/security/ntp_fix11.tar>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_fix11.tar> 

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.
           
For NTPv4:

| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 6.1.x | IJ10280s3b.181206.epkg.Z | key_w_fix |
| 7.1.x | IJ10280s3b.181206.epkg.Z | key_w_fix |
| 7.2.x | IJ10280s3b.181206.epkg.Z | key_w_fix |

| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.x | IJ10280s3b.181206.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
tar xvf ntp_fix11.tar 
cd ntp_fix11
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 file` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 000891c62f5e59c34909399d0ef4c74c72048a4fc1e7e50b66dedaa4fcf0ee87 | IJ10280s3b.181206.epkg.Z | key_w_csum |

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
 
* <http://aix.software.ibm.com/aix/efixes/security/ntp_advisory11.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/ntp_advisory11.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/ntp_advisory11.asc.sig>

## FIX AND INTERIM FIX INSTALLATION

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

If you would like to receive AIX Security Advisories via email,
please visit "My Notifications":

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
 
Complete CVSS v3 Guide:  <http://www.first.org/cvss/user-guide>

On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

IBM Secure Engineering Web Portal http://www.ibm.com/security/secure-engineering/bulletins.html

IBM Product Security Incident Response Blog https://www.ibm.com/blogs/psirt/

Security Bulletin: Vulnerabilities in NTPv4 affect AIX (CVE-2018-12327, CVE-2018-7170) https://www-01.ibm.com/support/docview.wss?uid=ibm10744497

# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Fri Dec 14 12:20:13 CST 2018

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




# IBM SECURITY ADVISORY

First Issued: Tue Jul 16 09:38:57 CDT 2019

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/openssh_advisory13.asc>
* <https://aix.software.ibm.com/aix/efixes/security/openssh_advisory13.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssh_advisory13.asc>

Security Bulletin:  Vulnerabilities in OpenSSH affect AIX (CVE-2018-20685
    CVE-2018-6109 CVE-2018-6110 CVE-2018-6111)

# SUMMARY

Vulnerabilities in OpenSSH affect AIX.

# VULNERABILITY DETAILS:

## CVEID: CVE-2019-6109
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6109
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6109
* *DESCRIPTION* 
  OpenSSH could allow a remote attacker to conduct spoofing 
  attacks, caused by missing character encoding in the progress display.
  A man-in-the-middle attacker could exploit this vulnerability to spoof
  scp client output.
* CVSS Base Score: 3.1
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/155488 for the current score.
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)

## CVEID: CVE-2019-6110
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6110
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6110
* *DESCRIPTION*
  OpenSSH could allow a remote attacker to conduct spoofing 
  attacks, caused by accepting and displaying arbitrary stderr output 
  from the scp server. A man-in-the-middle attacker could exploit this 
  vulnerability to spoof scp client output.
* CVSS Base Score: 3.1
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/155487 for the current score.
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)

## CVEID: CVE-2019-6111
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111
* *DESCRIPTION*
  OpenSSH could allow a remote attacker to overwrite 
  arbitrary files on the system, caused by missing received object 
  name validation by the scp client. The scp implementation accepts 
  arbitrary files sent by the server and a man-in-the-middle attacker 
  could exploit this vulnerability to overwrite unrelated files.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/155486 for the current score.
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N)

## CVEID: CVE-2018-20685
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20685
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20685
* *DESCRIPTION*
  In OpenSSH 7.9, scp.c in the scp client allows remote 
  SSH servers to bypass intended access restrictions via the 
  filename of . or an empty filename. The impact is modifying 
  the permissions of the target directory on the client side.
* CVSS Base Score: 7.5
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/155484 for the current score.
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)


# AFFECTED PRODUCTS AND VERSION:

* AIX 7.1, 7.2
* VIOS 2.2, 3.1

The following fileset levels are vulnerable:

key_fileset = osrcaix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| openssh.base.client | 4.0.0.5200 | 7.5.102.1600 | key_w_fs |
| openssh.base.server | 4.0.0.5200 | 7.5.102.1600 | key_w_fs |

Note:  To determine if your system is vulnerable, execute the following commands:

```
lslpp -L | grep -i openssh.base.client
lslpp -L | grep -i openssh.base.server
```


# REMEDIATION

## FIXES

A fix is available for CVE-2018-20685, CVE-2019-6109, and CVE-2019-6111, and it can be downloaded from:

* <https://www-01.ibm.com/marketing/iwm/iwm/web/pickUrxNew.do?source=aixbp&S_PKG=openssh>

Please see the WORKAROUNDS AND MITIGATIONS section for mitigation steps in response to CVE-2019-6110.

To extract the fixes from the tar file:

For Openssh 7.5 version -

```
zcat openssh-7.5.102.1800.tar.Z | tar xvf
```

Please refer to the Readme file to be aware of the changes that are part of the release.

IMPORTANT: If possible, it is recommended that a mksysb backup of the system be created.  Verify it is both bootable and
readable before proceeding.

Note that all the previously reported security vulnerability fixes are also included in above mentioned fileset level. Please refer
to the readme file (provided along with the fileset) for the complete list of vulnerabilities fixed.

To preview the fix installation:

```
installp -apYd . openssh
```

To install the fix package:

```
installp -aXYd . openssh
```

Published advisory OpenSSH signature file location:

* <http://aix.software.ibm.com/aix/efixes/security/openssh_advisory13.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/openssh_advisory13.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssh_advisory13.asc.sig>

```
openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]

openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```


## WORKAROUNDS AND MITIGATIONS

The potential impact of CVE-2019-6110 may be mitigated by using the sftp command in place of the scp command.


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing purposes.

If you would like to receive AIX Security Advisories via email, please visit "My Notifications":

* <http://www.ibm.com/support/mynotifications>
* <https://www.ibm.com/support/mynotifications>

To view previously issued advisories, please visit:

* <http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>
* <https://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>

Contact IBM Support for questions related to this announcement:

* <http://ibm.com/support/>
* <https://ibm.com/support/>

To obtain the OpenSSL public key that can be used to verify the signed advisories and ifixes:

Download the key from our web page:

* <ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

# REFERENCES

Complete CVSS v3 Guide:
* <http://www.first.org/cvss/user-guide>
* <https://www.first.org/cvss/user-guide>

On-line Calculator v3:
* <http://www.first.org/cvss/calculator/3.0>
* <https://www.first.org/cvss/calculator/3.0>

# RELATED INFORMATION

IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>

IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>

Security Bulletin: Vulnerabilities in OpenSSH affect AIX <https://www-01.ibm.com/support/docview.wss?uid=ibm10872060>

# ACKNOWLEDGEMENTS

None.

# CHANGE HISTORY

First Issued: Tue Jul 16 09:38:57 CDT 2019

The CVSS Environment Score is customer environment specific and will
ultimately impact the Overall CVSS Score. Customers can evaluate the
impact of this vulnerability in their environments by accessing the links
in the Reference section of this Flash.

Note: According to the Forum of Incident Response and Security Teams
(FIRST), the Common Vulnerability Scoring System (CVSS) is an "industry
open standard designed to convey vulnerability severity and help to
determine urgency and priority of response." IBM PROVIDES THE CVSS SCORES
"AS IS" WITHOUT WARRANTY OF ANY KIND, INCLUDING THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. CUSTOMERS ARE
RESPONSIBLE FOR ASSESSING THE IMPACT OF ANY ACTUAL OR POTENTIAL SECURITY
VULNERABILITY.






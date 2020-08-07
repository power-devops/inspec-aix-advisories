# IBM SECURITY ADVISORY

First Issued: Wed Oct 24 11:28:50 CDT 2018

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/openssh_advisory12.asc>
* <https://aix.software.ibm.com/aix/efixes/security/openssh_advisory12.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssh_advisory12.asc>

Security Bulletin:  Vulnerability in OpenSSH affects AIX (CVE-2018-15473)

# SUMMARY

Vulnerability in OpenSSH affects AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2018-15473
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15473
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15473
* *DESCRIPTION*
  OpenSSH could allow a remote attacker to obtain sensitive 
  information, caused by different responses to valid and invalid 
  authentication attempts. By sending a specially crafted request, an 
  attacker could exploit this vulnerability to enumerate valid usernames.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/148397 for the current score.
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)


# AFFECTED PRODUCTS AND VERSION:

* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x

The following fileset levels are vulnerable:

key_fileset = osrcaix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| openssh.base.client | 4.0.0.5200 | 7.5.102.1500 | key_w_fs |
| openssh.base.server | 4.0.0.5200 | 7.5.102.1500 | key_w_fs |

Note:  To determine if your system is vulnerable, execute the following commands:

```
lslpp -L | grep -i openssh.base.client
lslpp -L | grep -i openssh.base.server
```


# REMEDIATION

## A. FIXES

Fixes are available.  The fixes can be downloaded via ftp and http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/openssh_fix12.tar>
* <http://aix.software.ibm.com/aix/efixes/security/openssh_fix12.tar>
* <https://aix.software.ibm.com/aix/efixes/security/openssh_fix12.tar>

The links above are to a tar file containing this signed advisory, 
interim fixes, and OpenSSL signatures for each interim fix.
These fixes below include prerequisite checking. This will enforce
the correct mapping between the fixes and AIX releases.

Note that the tar file contains Interim fixes that are based on OpenSSH version as given below. 

You must be on the 'prereq for installation' level before applying
the interim fix. This may require installing a new level(prereq 
version) first.
            

| AIX Level | Interim Fix (*.Z) | Fileset Name (prereq for installation) | KEY |
| --------- | ----------------- | -------------------------------------- | --- |
| 5.3, 6.1, 7.1, 7.2 | 15473_fix.180919.epkg.Z | openssh.base (7.5.102.1500 version) | key_w_fix |

| VIOS Level | Interim Fix (*.Z) | Fileset Name (prereq for installation) | KEY |
| ---------- | ----------------- | -------------------------------------- | --- |
| 2.2.x | 15473_fix.180919.epkg.Z | openssh.base (7.5.102.1500 version) | key_w_fix |


Latest level of OpenSSH fileset is available from the web download site:
<https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=aixbp&lang=en_US&S_PKG=openssh&cp=UTF-8>

           
To extract the fix from the tar file:

```
tar xvf openssh_fix12.tar
cd openssh_fix12
```

Verify you have retrieved the fix intact:

The checksums below were generated using the `openssl dgst -sha256 file` command is the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 45ac81fc8766c41a7244ec2481ffa38aa90ca1b7c99b0b0acb1e4d82826b842a | 15473_fix.180919.epkg.Z | key_w_csum |


Published advisory OpenSSH signature file location:

* <http://aix.software.ibm.com/aix/efixes/security/openssh_advisory12.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/openssh_advisory12.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssh_advisory12.asc.sig>

```
openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```


## B. FIX AND INTERIM FIX INSTALLATION

After applying fix, IBM recommends that you regenerate your SSH keys as a precaution. 

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


# WORKAROUNDS AND MITIGATIONS

None.


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

To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page:

<ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.


# REFERENCES

Complete CVSS v3 Guide:
* <http://www.first.org/cvss/user-guide>
* <https://www.first.org/cvss/user-guide>

On-line Calculator v3:
* <http://www.first.org/cvss/calculator/3.0>
* <https://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

Security Bulletin: Vulnerability in OpenSSH affects AIX (CVE-2018-15473) <https://www-01.ibm.com/support/docview.wss?uid=ibm10733751>


# ACKNOWLEDGEMENTS

None


# CHANGE HISTORY

First Issued: Wed Oct 24 11:28:50 CDT 2018


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






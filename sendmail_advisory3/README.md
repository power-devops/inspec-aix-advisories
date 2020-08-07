# IBM SECURITY ADVISORY

First Issued: Fri Apr  6 11:18:40 CDT 2018 

Updated: Mon Sep 17 09:18:47 CDT 2018

Update: Clarified that AIX 7.2 TL0 SP6 and bos.net.tcp.sendmail fileset level
   7.2.0.3 are impacted. An iFix for AIX 7.2 TL0 SP6 is now available.

The most recent version of this document is available here:

<http://aix.software.ibm.com/aix/efixes/security/sendmail_advisory3.asc>

<https://aix.software.ibm.com/aix/efixes/security/sendmail_advisory3.asc>

<ftp://aix.software.ibm.com/aix/efixes/security/sendmail_advisory3.asc>

Security Bulletin:  Vulnerability in sendmail impacts AIX (CVE-2014-3956)
 
# SUMMARY

There is a vulnerability in sendmail that impacts AIX.

# VULNERABILITY DETAILS:

## CVEID: CVE-2014-3956
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3956
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3956
* **DESCRIPTION**: 
  The sm_close_on_exec function in conf.c in sendmail before 
  8.14.9 has arguments in the wrong order, and consequently skips 
  setting expected FD_CLOEXEC flags, which allows local users to access 
  unintended high-numbered file descriptors via a custom mail-delivery 
  program.  
* CVSS Base Score: 2.1 
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/93592> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (AV:L/AC:L/Au:N/C:N/I:P/A:N)


# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX  5.3, 6.1, 7.1, 7.2
* VIOS 2.2
        
The following fileset levels are vulnerable:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.client | 5.3.12.0 | 5.3.12.10 | key_w_fs |
| bos.net.tcp.server | 5.3.12.0 | 5.3.12.6 | key_w_fs |
| bos.net.tcp.client | 6.1.9.0 | 6.1.9.315 | key_w_fs |
| bos.net.tcp.client | 7.1.4.0 | 7.1.4.32 | key_w_fs |
| bos.net.tcp.client | 7.1.5.0 | 7.1.5.15 | key_w_fs |
| bos.net.tcp.sendmail | 7.2.0.0 | 7.2.0.3 | key_w_fs |
| bos.net.tcp.sendmail | 7.2.1.0 | 7.2.1.1 | key_w_fs |
| bos.net.tcp.sendmail | 7.2.2.0 | 7.2.2.15 | key_w_fs |
        
Note:  To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  ```lslpp -L | grep -i bos.net.tcp.client```

# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 5.3.12 | IJ03273 | ** | N/A | key_w_apar |
| 6.1.9 | IJ02915 | ** | SP12 | key_w_apar |
| 7.1.4 | IJ02917 | ** | SP7 | key_w_apar |
| 7.1.5 | IJ03121 | ** | SP4 | key_w_apar |
| 7.2.0 | IJ02918 | ** | N/A | key_w_apar |
| 7.2.1 | IJ02919 | ** | SP5 | key_w_apar |
| 7.2.2 | IJ02920 | ** | SP3 | key_w_apar |

| VIOS Level | APAR | Availability | SP |
| ---------- | ---- | ------------ | -- |
2.2.4     IJ02915    **          N/A
2.2.5     IJ02915    **          2.2.5.50
2.2.6     IJ02915    **          2.2.6.30
            
Please refer to AIX support lifecycle information page for 
availability of Service Packs: <http://www-01.ibm.com/support/docview.wss?uid=isg3T1012517>

Subscribe to the APARs here:

* <http://www.ibm.com/support/docview.wss?uid=isg1IJ03273>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ02915>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ02917>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ03121>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ02918>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ02919>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ02920>

* <https://www.ibm.com/support/docview.wss?uid=isg1IJ03273>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ02915>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ02917>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ03121>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ02918>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ02919>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ02920>

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

Fixes are available.

The fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/sendmail_fix3.tar>
* <http://aix.software.ibm.com/aix/efixes/security/sendmail_fix3.tar>
* <https://aix.software.ibm.com/aix/efixes/security/sendmail_fix3.tar>

The links above are to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.
          
Please note that the below table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.1.4.5 is AIX 7100-04-05.
 
| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 5.3.12.9 | IJ03273s9a.180116.epkg.Z | key_w_fix |
| 6.1.9.9 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 6.1.9.10 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 6.1.9.11 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 7.1.4.3 | IJ02917s3a.180105.epkg.Z | key_w_fix |
| 7.1.4.4 | IJ02917s3a.180105.epkg.Z | key_w_fix |
| 7.1.4.5 | IJ02917s3a.180105.epkg.Z | key_w_fix |
| 7.1.5.0 | IJ03121s0a.180110.epkg.Z | key_w_fix |
| 7.1.5.1 | IJ03121s0a.180110.epkg.Z | key_w_fix |
| 7.1.5.2 | IJ03121s0a.180110.epkg.Z | key_w_fix |
| 7.2.0.3 | IJ02918s3a.180108.epkg.Z | key_w_fix |
| 7.2.0.4 | IJ02918s3a.180108.epkg.Z | key_w_fix |
| 7.2.0.5 | IJ02918s3a.180108.epkg.Z | key_w_fix |
| 7.2.0.6 | IJ02918sp6.180913.epkg.Z | key_w_fix |
| 7.2.1.1 | IJ02919s1a.180108.epkg.Z | key_w_fix |
| 7.2.1.2 | IJ02919s1a.180108.epkg.Z | key_w_fix |
| 7.2.1.3 | IJ02919s1a.180108.epkg.Z | key_w_fix |
| 7.2.2.0 | IJ02920s0a.180110.epkg.Z | key_w_fix |
| 7.2.2.1 | IJ02920s0a.180110.epkg.Z | key_w_fix |
| 7.2.2.2 | IJ02920s0a.180110.epkg.Z | key_w_fix |


| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- | 
| 2.2.4.40 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 2.2.4.50 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 2.2.5.20 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 2.2.5.30 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 2.2.6.10 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 2.2.6.20 | IJ02915s9a.180110.epkg.Z | key_w_fix |
| 2.2.6.21 | IJ02915s9a.180110.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
tar xvf sendmail_fix3.tar
cd sendmail_fix3
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the
```openssl dgst -sha256 [filename]``` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 2987f7b0b4c549c958f6919974adf104452f9179a4e004c5f862d2473e751dfc | IJ02915s9a.180110.epkg.Z | key_w_csum |
| fbb7fc0fcbb30d6ccd2e1761c4682cf7e0252aeb64e60493e12d48f6c44510b0 | IJ02917s3a.180105.epkg.Z | key_w_csum |
| a0e3e1fbf9f7015ef72ffe181c7995862fb9f52d901ae3d7b0e8a98ae0af7994 | IJ02918s3a.180108.epkg.Z | key_w_csum |
| 9bbc538083702bd8bc574560d09b07c8dc061e07a14329dc1e6759ccba516f9c | IJ02918sp6.180913.epkg.Z | key_w_csum |
| bb2c7189784b734808aa637cf7ecfec5bd816cb42d9e5d812ac8e09abba6299d | IJ02919s1a.180108.epkg.Z | key_w_csum |
| 4a907f461a36a1a63941b0cca8992b366d71197f7d47c63e425d5614ac072157 | IJ02920s0a.180110.epkg.Z | key_w_csum |
| 4d95acdd312b233cedb5e106dfcdb8ac2266a11c402837545ea4963f929e7515 | IJ03121s0a.180110.epkg.Z | key_w_csum |
| 6663891d15e91f5f316e4f73c2a7e0d23dca31df2508e98cd0cc06bb227da55b | IJ03273s9a.180116.epkg.Z | key_w_csum |
                        
These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at <http://ibm.com/support/> and describe the discrepancy.
           
```
openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
 
openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
````

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/sendmail_advisory3.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/sendmail_advisory3.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/sendmail_advisory3.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

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

* <http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html>
* <https://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html>

To preview an interim fix installation:

```
            emgr -e epkg_name -p         # where epkg_name is the name of the
                                         # interim fix package being previewed.
```

To install an interim fix package:

```
            emgr -e epkg_name -X         # where epkg_name is the name of the
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

* <http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt>
* <https://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

# REFERENCES
 
* Complete CVSS v3 Guide: 
  * <http://www.first.org/cvss/user-guide>
  * <https://www.first.org/cvss/user-guide>

* On-line Calculator v3:
  * <http://www.first.org/cvss/calculator/3.0>
  * <https://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

Security Bulletin: Vulnerability in sendmail impacts AIX (CVE-2014-3956)
<http://www-01.ibm.com/support/docview.wss?uid=isg3T1027341>


# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Fri Apr  6 11:18:40 CDT 2018 

Updated: Mon Sep 17 09:18:47 CDT 2018

Update: Clarified that AIX 7.2 TL0 SP6 and bos.net.tcp.sendmail fileset level 7.2.0.3 are impacted. An iFix for AIX 7.2 TL0 SP6 is now available.


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


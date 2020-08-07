# IBM SECURITY ADVISORY

First Issued: Mon Apr 30 11:00:38 CDT 2018

The most recent version of this document is available here:

<http://aix.software.ibm.com/aix/efixes/security/openssl_advisory26.asc>

<https://aix.software.ibm.com/aix/efixes/security/openssl_advisory26.asc>

<ftp://aix.software.ibm.com/aix/efixes/security/openssl_advisory26.asc>


Security Bulletin: Vulnerability in OpenSSL affects AIX (CVE-2018-0739) 


# SUMMARY

There is a vulnerability in OpenSSL used by AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2018-0739 
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0739
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0739
* **DESCRIPTION**
  Constructed ASN.1 types with a recursive definition (such
  as can be found in PKCS7) could eventually exceed the stack given 
  malicious input with excessive recursion. This could result in a 
  Denial Of Service attack. 
* CVSS Base Score: 5.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/140847 for the current score 
* CVSS Environmental Score: Undefined
* CVSS Vector:(CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)


# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x

The following fileset levels are vulnerable:
        
key_fileset = osrcaix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| openssl.base | 1.0.2.500 | 1.0.2.1300 | key_w_fs |
| openssl.base | 20.13.102.1000 | 20.13.102.1300 | key_w_fs |

Note:  

A. 0.9.8, 1.0.1 OpenSSL versions are out-of-support. Customers are advised to upgrade to currently supported OpenSSL 1.0.2 version.

B. Latest level of OpenSSL fileset is available from the web download site: 
<https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=aixbp&lang=en_US&S_PKG=openssl&cp=UTF-8>
  
To find out whether the affected filesets are installed on your systems, 
refer to the lslpp command found in the AIX user's guide.

Example:  

    lslpp -L | grep -i openssl.base

# REMEDIATION

## FIXES

The fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/openssl_fix26.tar>
* <http://aix.software.ibm.com/aix/efixes/security/openssl_fix26.tar>
* <https://aix.software.ibm.com/aix/efixes/security/openssl_fix26.tar>

The links above are to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.
            
Note that the tar file contains Interim fixes that are based on 
OpenSSL version, and AIX OpenSSL fixes are cumulative.

You must be on the 'prereq for installation' level before
applying the interim fix. This may require installing a new
level(prereq version) first.


| AIX Level | Interim Fix (*.Z) | Fileset Name(prereq for installation) | KEY |
| --------- | ----------------- | ------------------------------------- | --- |
| 5.3, 6.1, 7.1, 7.2 | 102ma_ifix.180410.epkg.Z | openssl.base(1.0.2.1300) | key_w_fix |
| 5.3, 6.1, 7.1, 7.2 | fips_102ma.180410.epkg.Z | openssl.base(20.13.102.1300) | key_w_fix |

| VIOS Level | Interim Fix (*.Z) | Fileset Name(prereq for installation) | KEY |
| ---------- | ----------------- | ------------------------------------- | --- |
| 2.2.* | 102ma_ifix.180410.epkg.Z | openssl.base(1.0.2.1300) | key_w_fix |
| 2.2.* | fips_102ma.180410.epkg.Z | openssl.base(20.13.102.1300) | key_w_fix |

            
To extract the fixes from the tar file:

```
    tar xvf openssl_fix26.tar
    cd openssl_fix26
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 file` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| bfd40e466a6c7976fcf0cb46474087c550c043dc98b0be57689975388100bfdf | 102ma_ifix.180410.epkg.Z | key_w_csum |
| ee752e4a70cd46295141d7441a99e019db0391f6539881c5d185433dd0cd42ae | fips_102ma.180410.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM AIX Support at
https://ibm.com/support/ and describe the discrepancy.
            
```
    openssl dgst -sha1 -verify <pubkey_file> -signature <advisory_file>.sig <advisory_file>
    openssl dgst -sha1 -verify <pubkey_file> -signature <ifix_file>.sig <ifix_file>
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/openssl_advisory26.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/openssl_advisory26.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssl_advisory26.asc.sig>

## FIX AND INTERIM FIX INSTALLATION

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

## WORKAROUNDS AND MITIGATIONS

None.


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing purposes.

Advisories via email,
please visit "My Notifications":

* http://www.ibm.com/support/mynotifications
* https://www.ibm.com/support/mynotifications

To view previously issued advisories, please visit:

* http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq
* https://www14.software.ibm.com/webapp/set2/subscriptions/onvdq
 
Contact IBM Support for questions related to this announcement:

* http://ibm.com/support/
* https://ibm.com/support/

To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page:

* http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt
* https://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt

Please contact your local IBM AIX support center for any assistance.


# REFERENCES
 
Complete CVSS v3 Guide:  
* http://www.first.org/cvss/user-guide
* https://www.first.org/cvss/user-guide

On-line Calculator v3:
* http://www.first.org/cvss/calculator/3.0
* https://www.first.org/cvss/calculator/3.0


# RELATED INFORMATION

Security Bulletin: Vulnerability in OpenSSL affects AIX (CVE-2018-0739)
<http://www-01.ibm.com/support/docview.wss?uid=isg3T1027517>


# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Mon Apr 30 11:00:38 CDT 2018


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





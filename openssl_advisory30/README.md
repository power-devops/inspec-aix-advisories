# IBM SECURITY ADVISORY

First Issued: Tue Apr 16 10:48:55 CDT 2019

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/openssl_advisory30.asc>
* <https://aix.software.ibm.com/aix/efixes/security/openssl_advisory30.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssl_advisory30.asc>


Security Bulletin: Vulnerability in OpenSSL affects AIX (CVE-2019-1559)

## SUMMARY

There is a vulnerability in OpenSSL used by AIX.

## VULNERABILITY DETAILS

### CVEID: CVE-2019-1559
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1559>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1559>
* *DESCRIPTION* 
  OpenSSL could allow a remote attacker to obtain sensitive 
  information, caused by the failure to immediately close the TCP 
  connection after the hosts encounter a zero-length record with valid 
  padding. An attacker could exploit this vulnerability using a 0-byte 
  record padding-oracle attack to decrypt traffic.
* CVSS Base Score: 5.8
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/157514> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector:(CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N)

## AFFECTED PRODUCTS AND VERSIONS
 
* AIX 7.1, 7.2
* VIOS 2.2.x

The following fileset levels are vulnerable:
        
key_fileset = osrcaix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| openssl.base | 1.0.2.500 | 1.0.2.1601 | key_w_fs |
| openssl.base | 20.13.102.1000 | 20.16.102.1600 | key_w_fs |

Note:

A. 0.9.8, 1.0.1 OpenSSL versions are out-of-support. Customers are
   advised to upgrade to currently supported OpenSSL 1.0.2 version.

B. Latest level of OpenSSL fileset is available from the web download site:
   <https://www-01.ibm.com/marketing/iwm/iwm/web/pickUrxNew.do?source=aixbp&S_PKG=openssl>
  
To find out whether the affected filesets are installed on your systems,
refer to the lslpp command found in the AIX user's guide.

Example:  

```
lslpp -L | grep -i openssl.base
```

## REMEDIATION

### A. FIXES

The fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/openssl_fix30.tar>
* <http://aix.software.ibm.com/aix/efixes/security/openssl_fix30.tar>
* <https://aix.software.ibm.com/aix/efixes/security/openssl_fix30.tar>

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
| 7.1, 7.2 | 102pa_mfix.190318.epkg.Z | openssl.base(1.0.2.1601) | key_w_fix |
| 7.1, 7.2 | fips_102pa.190318.epkg.Z | openssl.base(20.16.102.1600) | key_w_fix |

| VIOS Level | Interim Fix (*.Z) | Fileset Name(prereq for installation) | KEY |
| ---------- | ----------------- | ------------------------------------- | --- |
| 2.2.x | 102pa_mfix.190318.epkg.Z | openssl.base(1.0.2.1601) | key_w_fix |
| 2.2.x | fips_102pa.190318.epkg.Z | openssl.base(20.16.102.1600) | key_w_fix |

To extract the fixes from the tar file:

```
tar xvf openssl_fix30.tar
cd openssl_fix30
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the
`openssl dgst -sha256 file` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| cf3418b3cb99e678c47e334460782e4e4eef0a67a32b10612cd4709006ebf4e0 | 102pa_mfix.190318.epkg.Z | key_w_csum |
| 4de4c7534856d1192cf7f80bb5ca0bef8a8b514f78afffbcdf8397959f55163e | fips_102pa.190318.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM AIX Support at
<https://ibm.com/support/> and describe the discrepancy.

```
openssl dgst -sha1 -verify <pubkey_file> -signature <advisory_file>.sig <advisory_file>
```

```
openssl dgst -sha1 -verify <pubkey_file> -signature <ifix_file>.sig <ifix_file>
```

Published advisory OpenSSL signature file location:

* <http://aix.software.ibm.com/aix/efixes/security/openssl_advisory30.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/openssl_advisory30.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssl_advisory30.asc.sig>

### B. FIX AND INTERIM FIX INSTALLATION

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

## WORKAROUNDS AND MITIGATIONS

None.

## CONTACT US

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

* <ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

## REFERENCE

Complete CVSS v3 Guide:
* <http://www.first.org/cvss/user-guide>
* <https://www.first.org/cvss/user-guide>

On-line Calculator v3:
* <http://www.first.org/cvss/calculator/3.0>
* <https://www.first.org/cvss/calculator/3.0>

## RELATED INFORMATION

Security Bulletin: Vulnerability in OpenSSL affects AIX (CVE-2019-1559)
<https://www-01.ibm.com/support/docview.wss?uid=ibm10878172>


## ACKNOWLEDGEMENTS

None.


## CHANGE HISTORY

First Issued: Tue Apr 16 10:48:55 CDT 2019


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


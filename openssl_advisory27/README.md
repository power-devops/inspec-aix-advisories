# IBM SECURITY ADVISORY

First Issued: Mon Jul  2 11:24:30 CDT 2018

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/openssl_advisory27.asc>
* <https://aix.software.ibm.com/aix/efixes/security/openssl_advisory27.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssl_advisory27.asc>


Security Bulletin: Vulnerability in OpenSSL affects AIX (CVE-2018-0737) 


# SUMMARY

There is a vulnerability in OpenSSL used by AIX.


# VULNERABILITY DETAILS

## CVEID: CVE-2018-0737 
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0737>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0737>
* **DESCRIPTION**
  The OpenSSL RSA Key generation algorithm has been shown to 
  be vulnerable to a cache timing side channel attack. An attacker with 
  sufficient access to mount cache timing attacks during the RSA key 
  generation process could recover the private key.  
* CVSS Base Score: 3.3 
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/141679 for the current score 
* CVSS Environmental Score: Undefined
* CVSS Vector:NA


# AFFECTED PRODUCTS AND VERSIONS
 
* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x

The following fileset levels are vulnerable:
        
key_fileset = osrcaix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| openssl.base | 1.0.2.500 | 1.0.2.1300 | key_w_fs |
| openssl.base | 20.13.102.1000 | 20.13.102.1300 | key_w_fs |

Note:  

A. 0.9.8, 1.0.1 OpenSSL versions are out-of-support. Customers are 
advised to upgrade to currently supported OpenSSL 1.0.2 version.

B. Latest level of OpenSSL fileset is available from the web download site:
https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=aixbp&lang=en_US&S_PKG=openssl&cp=UTF-8
  
To find out whether the affected filesets are installed on your systems, 
refer to the lslpp command found in the AIX user's guide.

Example:  

    lslpp -L | grep -i openssl.base


# REMEDIATION

## FIXES

A fix is available, and it can be downloaded from:

<https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp>

To extract the fixes from the tar file:

* For Openssl 1.0.2 version - `zcat openssl-1.0.2.1500.tar.Z | tar xvf -`

* For 1.0.2 FIPS capable openssl version - `zcat openssl-20.13.102.1500.tar.Z | tar xvf -`
                 

*IMPORTANT*: If possible, it is recommended that a mksysb backup
of the system be created.  Verify it is both bootable and
readable before proceeding.

Note that all the previously reported security vulnerability fixes
are also included in above mentioned fileset level. Please refer to 
the readme file (provided along with the fileset) for the complete
list of vulnerabilities fixed.

To preview the fix installation:


    installp -apYd . openssl


To install the fix package:


    installp -aXYd . openssl
                        
            
```
    openssl dgst -sha1 -verify <pubkey_file> -signature <advisory_file>.sig <advisory_file>

    openssl dgst -sha1 -verify <pubkey_file> -signature <ifix_file>.sig <ifix_file>
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/openssl_advisory27.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/openssl_advisory27.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/openssl_advisory27.asc.sig>

            
# WORKAROUNDS AND MITIGATIONS

None.


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing purposes.

If you would like to receive AIX Security Advisories via email,
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
 
* Complete CVSS v3 Guide:  
  * http://www.first.org/cvss/user-guide
  * https://www.first.org/cvss/user-guide
* On-line Calculator v3:
  * http://www.first.org/cvss/calculator/3.0
  * https://www.first.org/cvss/calculator/3.0


# RELATED INFORMATION

Security Bulletin: Vulnerability in OpenSSL affects AIX (CVE-2018-0737) http://www.ibm.com/support/docview.wss?uid=ibm10713441


# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Mon Jul  2 11:24:30 CDT 2018


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







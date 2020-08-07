IBM SECURITY ADVISORY

First Issued: Fri Dec 14 12:09:04 CST 2018

The most recent version of this document is available here:

http://aix.software.ibm.com/aix/efixes/security/itds_advisory2.asc
https://aix.software.ibm.com/aix/efixes/security/itds_advisory2.asc
ftp://aix.software.ibm.com/aix/efixes/security/itds_advisory2.asc

Security Bulletin: Vulnerabilities in GSKit affect IBM Tivoli Directory
    Server and IBM Security Directory Server for AIX

===============================================================================

SUMMARY:

    There are multiple vulnerabilities in GSKit that affect IBM Tivoli
    Directory Server and IBM Security Directory Server for AIX. 

===============================================================================

VULNERABILITY DETAILS:

    CVEID: CVE-2018-1388
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1388
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1388
    DESCRIPTION: GSKit V7 may disclose side channel information via 
        discrepencies between valid and invalid PKCS#1 padding. 
    CVSS Base Score: 9.1
    CVSS Temporal Score: See
        https://exchange.xforce.ibmcloud.com/vulnerabilities/138212
        for the current score
    CVSS Environmental Score*: Undefined
    CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

    CVEID: CVE-2018-1427
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1427
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1427
    DESCRIPTION: IBM GSKit contains several enviornment variables that a local
        attacker could overflow and cause a denial of service.
    CVSS Base Score: 6.2
    CVSS Temporal Score: See
        https://exchange.xforce.ibmcloud.com/vulnerabilities/139072
        for the current score
    CVSS Environmental Score*: Undefined
    CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

    CVEID: CVE-2018-1426
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1426
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1426
    DESCRIPTION: IBM GSKit duplicates the PRNG state across fork() system 
        calls when multiple ICC instances are loaded which could result in 
        duplicate Session IDs and a risk of duplicate key material.
    CVSS Base Score: 7.4
    CVSS Temporal Score: See
        https://exchange.xforce.ibmcloud.com/vulnerabilities/139071
        for the current score
    CVSS Environmental Score*: Undefined
    CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

    CVEID: CVE-2016-0702
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0702
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0702
    DESCRIPTION: OpenSSL could allow a local attacker to obtain sensitive 
        information, caused by a side-channel attack against a system based on
        the Intel Sandy-Bridge microarchitecture. An attacker could exploit 
        this vulnerability to recover RSA keys.
    CVSS Base Score: 2.9
    CVSS Temporal Score: See
        https://exchange.xforce.ibmcloud.com/vulnerabilities/111144
        for the current score
    CVSS Environmental Score*: Undefined
    CVSS Vector: (CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

    CVEID: CVE-2018-1447
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1447
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1447
    DESCRIPTION: The GSKit CMS KDB logic fails to salt the hash function 
        resulting in weaker than expected protection of passwords. A weak 
        password may be recovered. Note: After update the customer should 
        change password to ensure the new password is stored more securely. 
        Products should encourage customers to take this step as a high 
        priority action.
    CVSS Base Score: 5.1
    CVSS Temporal Score: See
        https://exchange.xforce.ibmcloud.com/vulnerabilities/139972
        for the current score
    CVSS Environmental Score*: Undefined
    CVSS Vector: (CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)


AFFECTED PRODUCTS AND VERSIONS:

        AIX 5.3, 6.1, 7.1, 7.2
        VIOS 2.2.x

        The following fileset levels (VRMF) are vulnerable, if the
        respective IBM Tivoli Directory Server (ITDS) or IBM Security Directory
        Server (ISDS) version is installed:
        For ITDS 6.2.0:    Less than 6.2.0.56
        For ITDS 6.3.0:    Less than 6.3.0.49
        For ISDS 6.3.1:    Less than 6.3.1.24
        For ISDS 6.4.0:    Less than 6.4.0.16

        Note: To find out whether the affected ITDS or ISDS filesets are  
        installed on your systems, refer to the lslpp command found in AIX
        user's guide.

        Example:  lslpp -L | grep -i itds


REMEDIATION:

        Note: Recommended remediation is to always install the most recent
        package available for the respective IBM Tivoli Directory Server or
        IBM Security Directory Server version.

        IBM Tivoli Directory Server 6.2.0, 6.2.0.56 or later: 
    https://www.ibm.com/support/fixcentral/swg/selectFixes?parent=Security%2BSystems&product=ibm/Tivoli/Tivoli+Directory+Server&release=6.2.0.52&platform=AIX&function=all

        IBM Tivoli Directory Server 6.3.0, 6.3.0.49 or later:
    https://www.ibm.com/support/fixcentral/swg/selectFixes?parent=Security%2BSystems&product=ibm/Tivoli/Tivoli+Directory+Server&release=6.3.0.45&platform=AIX&function=all

        IBM Security Directory Server 6.3.1, 6.3.1.24 or later:
    https://www.ibm.com/support/fixcentral/swg/selectFixes?parent=Security%2BSystems&product=ibm/Tivoli/IBM+Security+Directory+Server&release=6.3.1.20&platform=AIX&function=all

        IBM Security Directory Server 6.4.0, 6.4.0.16 or later:
    https://www.ibm.com/support/fixcentral/swg/selectFixes?parent=Security%2BSystems&product=ibm/Tivoli/IBM+Security+Directory+Server&release=6.4.0.11&platform=AIX&function=all


WORKAROUNDS AND MITIGATIONS:

    None.


===============================================================================

CONTACT US:

    If you would like to receive AIX Security Advisories via email,
    please visit "My Notifications":

        http://www.ibm.com/support/mynotifications

    To view previously issued advisories, please visit:

        http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq

    Contact IBM Support for questions related to this announcement:

        http://ibm.com/support/
        https://ibm.com/support/

    To obtain the OpenSSL public key that can be used to verify the
    signed advisories and ifixes:

        Download the key from our web page:

    http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt

    Please contact your local IBM AIX support center for any
    assistance.


REFERENCES:

    Complete CVSS v2 Guide:
        http://www.first.org/cvss/v2/guide
    On-line Calculator v2:
        http://nvd.nist.gov/CVSS-v2-Calculator
    Complete CVSS v3 Guide:
        http://www.first.org/cvss/user-guide
    On-line Calculator v3:
        http://www.first.org/cvss/calculator/3.0


RELATED INFORMATION:

    Security Bulletin: Vulnerabilities in GSKit affect IBM Tivoli Directory
    Server and IBM Security Directory Server for AIX
        http://www-01.ibm.com/support/docview.wss?uid=ibm10788069


ACKNOWLEDGEMENTS:

    None.

CHANGE HISTORY:

    First Issued: Fri Dec 14 12:09:04 CST 2018


===============================================================================

*The CVSS Environment Score is customer environment specific and will
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





# IBM SECURITY ADVISORY

First Issued: Fri Jun 28 13:47:27 CDT 2019

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/java_apr2019_advisory.asc>
* <https://aix.software.ibm.com/aix/efixes/security/java_apr2019_advisory.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/java_apr2019_advisory.asc>

Security Bulletin: Multiple vulnerabilities in IBM Java SDK affect AIX

# SUMMARY

There are multiple vulnerabilities in IBM SDK Java Technology Edition,
Versions 7, 7.1, 8 that are used by AIX. These issues were disclosed
as part of the IBM Java SDK updates in April 2019.

# VULNERABILITY DETAILS

## CVEID: CVE-2019-10245
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10245
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10245
* *DESCRIPTION* 
  Eclipse OpenJ9 is vulnerable to a denial of service, caused 
  by the execution of a method past the end of bytecode array by the 
  Java bytecode verifier. A remote attacker could exploit this 
  vulnerability to cause the application to crash. 
* CVSS Base Score: 7.5
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/160010 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

## CVEID: CVE-2019-2684
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2684
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2684
* *DESCRIPTION* 
  An unspecified vulnerability in Oracle Java SE related to 
  the Java SE, Java SE Embedded RMI component could allow an 
  unauthenticated attacker to cause no confidentiality impact, high 
  integrity impact, and no availability impact.
* CVSS Base Score: 5.9
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/159776 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)

## CVEID: CVE-2019-2602
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2602
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2602
* *DESCRIPTION*
  An unspecified vulnerability in Oracle Java SE related to 
  the Java SE, Java SE Embedded Libraries component could allow an 
  unauthenticated attacker to cause a denial of service resulting in a 
  high availability impact using unknown attack vectors.
* CVSS Base Score: 7.5
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/159698 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

## CVEID: CVE-2019-2697
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2697
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2697
* *DESCRIPTION*
  An unspecified vulnerability in Oracle Java SE related to 
  the Java SE 2D component could allow an unauthenticated attacker to 
  take control of the system.
* CVSS Base Score: 8.1
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/159789 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

## CVEID: CVE-2019-2698
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2698
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2698
* *DESCRIPTION* 
  An unspecified vulnerability in Oracle Java SE related to 
  the Java SE 2D component could allow an unauthenticated attacker to 
  take control of the system.
* CVSS Base Score: 8.1
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/159790 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

# AFFECTED PRODUCTS AND VERSIONS

* AIX 7.1, 7.2
* VIOS 2.2.x

The following fileset levels (VRMF) are vulnerable, if the respective Java version is installed:

* For Java7:    Less than 7.0.0.645
* For Java7.1:  Less than 7.1.0.445
* For Java8:    Less than 8.0.0.535

Note: To find out whether the affected Java filesets are installed
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

```
lslpp -L | grep -i java
```

# REMEDIATION

Note: Recommended remediation is to always install the most recent
Java package available for the respective Java version.

IBM SDK, Java Technology Edition, Version 7 Service Refresh 10 Fix Pack 45 and subsequent releases:
* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+64-bit,+pSeries&function=all>

IBM SDK, Java Technology Edition, Version 7R1 Service Refresh 4 Fix Pack 45 and subsequent releases:
* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+64-bit,+pSeries&function=all>

IBM SDK, Java Technology Edition, Version 8 Service Refresh 5 Fix Pack 35 and subsequent releases:
* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+64-bit,+pSeries&function=all>

# WORKAROUNDS AND MITIGATIONS

None.

# CONTACT US

If you would like to receive AIX Security Advisories via email, please visit "My Notifications":

* http://www.ibm.com/support/mynotifications

To view previously issued advisories, please visit:

* http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq

Contact IBM Support for questions related to this announcement:

* http://ibm.com/support/
* https://ibm.com/support/

To obtain the OpenSSL public key that can be used to verify the signed advisories and ifixes:

Download the key from our web page:

* http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt

Please contact your local IBM AIX support center for any assistance.

# REFERENCES

* Complete CVSS v2 Guide: http://www.first.org/cvss/v2/guide
* On-line Calculator v2: http://nvd.nist.gov/CVSS-v2-Calculator
* Complete CVSS v3 Guide: http://www.first.org/cvss/user-guide
* On-line Calculator v3: http://www.first.org/cvss/calculator/3.0
* IBM Java SDK Security Bulletin: https://www-01.ibm.com/support/docview.wss?uid=ibm10882850


# RELATED INFORMATION

Security Bulletin: Multiple vulnerabilities in IBM Java SDK affect AIX <http://www-01.ibm.com/support/docview.wss?uid=ibm10884442>


# ACKNOWLEDGEMENTS

None.

# CHANGE HISTORY

First Issued: Fri Jun 28 13:47:27 CDT 2019

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




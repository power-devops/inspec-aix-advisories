# IBM SECURITY ADVISORY

First Issued: Wed Sep 19 08:42:00 CDT 2018

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/java_july2018_advisory.asc>
* <https://aix.software.ibm.com/aix/efixes/security/java_july2018_advisory.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/java_july2018_advisory.asc>

Security Bulletin: Multiple vulnerabilities in IBM Java SDK affect AIX

# SUMMARY

There are multiple vulnerabilities in IBM SDK Java Technology Edition,
Versions 7, 7.1, 8 that are used by AIX. These issues were disclosed
as part of the IBM Java SDK updates in July 2018.

# VULNERABILITY DETAILS

## CVE-2018-1517
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1517>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1517>
* **DESCRIPTION**
  A flaw in the java.math component in IBM SDK, Java Technology
  Edition may allow an attacker to inflict a denial-of-service attack
  with specially crafted String data.
* CVSS Base Score: 5.9
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/141681 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)

## CVE-2018-1656
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1656>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1656>
* **DESCRIPTION**
  The IBM Java Runtime Environment''s Diagnostic Tooling
  Framework for Java (DTFJ) does not protect against path traversal
  attacks when extracting compressed dump files.
* CVSS Base Score: 7.4
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/144882 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N)

## CVE-2018-2973
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2973>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2973>
* **DESCRIPTION**
  An unspecified vulnerability in Oracle Java SE related to the
  Java SE, Java SE Embedded JSSE component could allow an
  unauthenticated attacker to cause no confidentiality impact, high
  integrity impact, and no availability impact.
* CVSS Base Score: 5.9
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/146835 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)

## CVE-2018-2952
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2952>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2952>
* **DESCRIPTION**
  An unspecified vulnerability in Oracle Java SE related to the
  Java SE, Java SE Embedded, JRockit Concurrency component could allow
  an unauthenticated attacker to cause a denial of service resulting in
  a low availability impact using unknown attack vectors.
* CVSS Base Score: 3.7
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/146815 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L)

## CVE-2018-2940
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2940>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2940>
* **DESCRIPTION** 
  An unspecified vulnerability in Oracle Java SE related to the
  Java SE, Java SE Embedded Libraries component could allow an
  unauthenticated attacker to obtain sensitive information resulting in
  a low confidentiality impact using unknown attack vectors.
* CVSS Base Score: 4.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/146803 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)

## CVE-2018-2964
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2964>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-2964>
* **DESCRIPTION**
  An unspecified vulnerability in Oracle Java SE related to the
  Java SE Deployment component could allow an unauthenticated attacker
  to take control of the system.
* CVSS Base Score: 8.3
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/146827 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H)

## CVE-2018-12539
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12539>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12539>
* **DESCRIPTION**
  Eclipse OpenJ9 could allow a local attacker to gain elevated
  privileges on the system, caused by the failure to restrict the use
  of Java Attach API to connect to an Eclipse OpenJ9 or IBM JVM on the
  same machine and use Attach API operations to only the process owner.
  An attacker could exploit this vulnerability to execute untrusted
  native code and gain elevated privileges on the system.
* CVSS Base Score: 8.4
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/148389 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)


# AFFECTED PRODUCTS AND VERSIONS

* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x

 The following fileset levels (VRMF) are vulnerable, if the
 respective Java version is installed:

* For Java7:    Less than 7.0.0.630
* For Java7.1:  Less than 7.1.0.430
* For Java8:    Less than 8.0.0.521

Note: To find out whether the affected Java filesets are installed
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

    lslpp -L | grep -i java


# REMEDIATION

Note: Recommended remediation is to always install the most recent
Java package available for the respective Java version.

IBM SDK, Java Technology Edition, Version 7 Service Refresh 10 Fix Pack 30 and subsequent releases:

* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+64-bit,+pSeries&function=all>

IBM SDK, Java Technology Edition, Version 7R1 Service Refresh 4 Fix Pack 30 and subsequent releases:

* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+64-bit,+pSeries&function=all>

IBM SDK, Java Technology Edition, Version 8 Service Refresh 5 Fix Pack 21 and subsequent releases:

* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+64-bit,+pSeries&function=all>


# WORKAROUNDS AND MITIGATIONS

None.


# CONTACT US:

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

<http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.


# REFERENCES

* Complete CVSS v2 Guide: <http://www.first.org/cvss/v2/guide>
* On-line Calculator v2: <http://nvd.nist.gov/CVSS-v2-Calculator>
* Complete CVSS v3 Guide: <http://www.first.org/cvss/user-guide>
* On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

Security Bulletin: Multiple vulnerabilities in IBM Java SDK affect AIX
<http://www-01.ibm.com/support/docview.wss?uid=ibm10730909>


# ACKNOWLEDGEMENTS

None.

# CHANGE HISTORY

First Issued: Wed Sep 19 08:42:00 CDT 2018


The CVSS Environment Score is customer environment specific and will
ultimately impact the Overall CVSS Score. Customers can evaluate the impact
of this vulnerability in their environments by accessing the links in the
Reference section of this Security Bulletin.

**Disclaimer**

According to the Forum of Incident Response and Security Teams (FIRST), the
Common Vulnerability Scoring System (CVSS) is an "industry open standard
designed to convey vulnerability severity and help to determine urgency and
priority of response." IBM PROVIDES THE CVSS SCORES "AS IS" WITHOUT WARRANTY
OF ANY KIND, INCLUDING THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE. CUSTOMERS ARE RESPONSIBLE FOR ASSESSING THE IMPACT
OF ANY ACTUAL OR POTENTIAL SECURITY VULNERABILITY.




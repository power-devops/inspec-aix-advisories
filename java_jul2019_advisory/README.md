# IBM SECURITY ADVISORY

First Issued: Wed Oct  9 13:12:20 CDT 2019

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/java_july2019_advisory.asc>
* <https://aix.software.ibm.com/aix/efixes/security/java_july2019_advisory.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/java_july2019_advisory.asc>

Security Bulletin: Multiple vulnerabilities in IBM Java SDK affect AIX

## SUMMARY

There are multiple vulnerabilities in IBM SDK Java Technology Edition,
Versions 7, 7.1, 8 used by AIX. AIX has addressed the applicable CVEs.

## VULNERABILITY DETAILS

### CVEID: CVE-2019-11775
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11775>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11775>
* *DESCRIPTION*
  Eclipse OpenJ9 could allow a local attacker to gain elevated
  privileges on the system, caused by an error where the loop versioner
  fails to privatize a value that is pulled out of the loop by 
  versioning. An attacker could exploit this vulnerability to corrupt
  memory and trigger an out-of-array-bounds and perform invalid actions.
* CVSS Base Score: 8.4
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/164479> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

### CVEID: CVE-2019-11772
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11772>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11772>
* *DESCRIPTION* 
  Eclipse OpenJ9 could allow a local attacker to gain elevated
  privileges on the system, caused by an out-of-bounds write in the 
  String.getBytes method. An attacker could exploit this vulnerability
  to corrupt memory and write to any 32-bit address or beyond the end 
  of a byte array within Java code run under a SecurityManager.
* CVSS Base Score: 8.4
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163990> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

### CVEID: CVE-2019-2766
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2766>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2766>
* *DESCRIPTION* 
  An unspecified vulnerability in Oracle Java SE related to 
  the Java SE, Java SE Embedded Networking component could allow an
  unauthenticated attacker to obtain sensitive information resulting in
  a low confidentiality impact using unknown attack vectors.
* CVSS Base Score: 3.1
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163829> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)

### CVEID: CVE-2019-2786
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2786>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2786>
* *DESCRIPTION* 
  An unspecified vulnerability in Oracle Java SE related to
  the Java SE, Java SE Embedded Security component could allow an
  unauthenticated attacker to obtain sensitive information resulting in
  a low confidentiality impact using unknown attack vectors.
* CVSS Base Score: 3.4
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163849> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N)

### CVEID: CVE-2019-2816
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2816>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2816>
* *DESCRIPTION* 
  An unspecified vulnerability in Oracle Java SE related to
  the Java SE, Java SE Embedded Networking component could allow an
  unauthenticated attacker to cause low confidentiality impact, low
  integrity impact, and no availability impact.
* CVSS Base Score: 4.8
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163878> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N)

### CVEID: CVE-2019-2762
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2762>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2762>
* *DESCRIPTION* 
  An unspecified vulnerability in Oracle Java SE related to
  the Java SE, Java SE Embedded Utilities component could allow an
  unauthenticated attacker to cause a denial of service resulting in
  a low availability impact using unknown attack vectors.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163826> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)

### CVEID: CVE-2019-2769
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2769>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2769>
* *DESCRIPTION* 
  An unspecified vulnerability in Oracle Java SE related to
  the Java SE, Java SE Embedded Utilities component could allow an
  unauthenticated attacker to cause a denial of service resulting in
  a low availability impact using unknown attack vectors.
* CVSS Base Score: 5.3
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163832> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)

### CVEID: CVE-2019-7317
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7317>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7317>
* *DESCRIPTION* 
  Mozilla Firefox is vulnerable to a denial of service, caused
  by a use-after-free in the png_image_free function in the libpng 
  library. By persuading a victim to visit a specially-crafted Web site,
  a remote attacker could exploit this vulnerability to cause a denial
  of service.
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/161346> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

### CVEID: CVE-2019-4473
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-4473>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-4473>
* *DESCRIPTION* 
  Multiple binaries in IBM SDK, Java Technology Edition on 
  the AIX platform use insecure absolute RPATHs, which may facilitate 
  code injection and privilege elevation by local users.
* CVSS Base Score: 8.4
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163984> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

### CVEID: CVE-2019-11771
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11771>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11771>
* *DESCRIPTION* 
  Eclipse OpenJ9 could allow a local attacker to gain elevated
  privileges on the system, caused by the inclusion of unused RPATHS in
  AIX builds. An attacker could exploit this vulnerability to inject
  code and gain elevated privileges on the system.
* CVSS Base Score: 8.4
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/163989> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)


## AFFECTED PRODUCTS AND VERSIONS

* AIX 7.1, 7.2
* VIOS 2.2, 3.1

The following fileset levels (VRMF) are vulnerable, if the respective Java version is installed:

* For Java7:    Less than 7.0.0.650
* For Java7.1:  Less than 7.1.0.450
* For Java8:    Less than 8.0.0.540

Note: To find out whether the affected Java filesets are installed
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  ```lslpp -L | grep -i java```


## REMEDIATION

Note: Recommended remediation is to always install the most recent
Java package available for the respective Java version.

IBM SDK, Java Technology Edition, Version 7 Service Refresh 10 Fix Pack 50 and subsequent releases:
* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.0.0.0&platform=AIX+64-bit,+pSeries&function=all>

IBM SDK, Java Technology Edition, Version 7R1 Service Refresh 4 Fix Pack 50 and subsequent releases:
* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=7.1.0.0&platform=AIX+64-bit,+pSeries&function=all>

IBM SDK, Java Technology Edition, Version 8 Service Refresh 5 Fix Pack 40 and subsequent releases:
* 32-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+32-bit,+pSeries&function=all>
* 64-bit: <https://www-945.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm~WebSphere&product=ibm/IBM+SDKs+for+Java+Technology/Java+Standard+Edition+%28Java+SE%29&release=8.0.0.0&platform=AIX+64-bit,+pSeries&function=all>


## WORKAROUNDS AND MITIGATIONS

None.

## CONTACT US

If you would like to receive AIX Security Advisories via email, please visit "My Notifications":

* <http://www.ibm.com/support/mynotifications>

To view previously issued advisories, please visit:

* <http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>

Contact IBM Support for questions related to this announcement:

* <http://ibm.com/support/>
* <https://ibm.com/support/>

To obtain the OpenSSL public key that can be used to verify the signed advisories and ifixes:

Download the key from our web page:

* <http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

## REFERENCES

* Complete CVSS v2 Guide: <http://www.first.org/cvss/v2/guide>
* On-line Calculator v2: <http://nvd.nist.gov/CVSS-v2-Calculator>
* Complete CVSS v3 Guide: <http://www.first.org/cvss/user-guide>
* On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>
* IBM Java SDK Security Bulletin: <https://www.ibm.com/support/docview.wss?uid=ibm10960422>


## RELATED INFORMATION

Security Bulletin: Multiple vulnerabilities in IBM Java SDK affect AIX
<http://www-01.ibm.com/support/docview.wss?uid=ibm11072984>


## ACKNOWLEDGEMENTS

None.

## CHANGE HISTORY

First Issued: Wed Oct  9 13:12:20 CDT 2019

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



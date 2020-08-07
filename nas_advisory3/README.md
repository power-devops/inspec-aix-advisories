# IBM SECURITY ADVISORY

First Issued : Thu May 21 05:06:05 CDT 2015

The most recent version of this document is available here:

<http://aix.software.ibm.com/aix/efixes/security/nas_advisory3.asc>
<https://aix.software.ibm.com/aix/efixes/security/nas_advisory3.asc>
<ftp://aix.software.ibm.com/aix/efixes/security/nas_advisory3.asc>

# VULNERABILITY SUMMARY

## 1.VULNERABILITY

**AIX NAS denial of service vulnerability**

* PLATFORMS: *AIX 5.3, 6.1 and 7.1, VIOS 2.2*
* SOLUTION: *Apply the fix as described below.*
* THREAT: *See below*
* CVE Numbers: *CVE-2014-5352*
* Reboot required? *NO*
* Workarounds? *NO*
* Protected by FPM? *NO*
* Protected by SED? *NO*

## 2. VULNERABILITY

**AIX NAS Denial of Service via a zero-byte version string or by omitting the '\0' character**

* PLATFORMS: *AIX 5.3, 6.1 and 7.1, VIOS 2.2*
* SOLUTION: *Apply the fix as described below.*
* THREAT: *See below*
* CVE Numbers: *CVE-2014-5355*
* Reboot required? *NO*
* Workarounds? *NO*
* Protected by FPM? *NO*
* Protected by SED? *NO*

## 3. VULNERABILITY

**AIX NAS Denial of Service via malformed XDR data**

* PLATFORMS: *AIX 5.3, 6.1 and 7.1, VIOS 2.2*
* SOLUTION: *Apply the fix as described below.*
* THREAT: *See below*
* CVE Numbers: *CVE-2014-9421*
* Reboot required? *NO*
* Workarounds? *NO*
* Protected by FPM? *NO*
* Protected by SED? *NO*

## 4. VULNERABILITY

**AIX NAS allows remote users to obtain administrative access by leveraging access to a two-component principal**

* PLATFORMS: *AIX 5.3, 6.1 and 7.1, VIOS 2.2*
* SOLUTION: *Apply the fix as described below.*
* THREAT: *See below*
* CVE Numbers: *CVE-2014-9422*
* Reboot required? *NO*
* Workarounds? *NO*
* Protected by FPM? *NO*
* Protected by SED? *NO*

## 5. VULNERABILITY

**AIX NAS allows remote users to obtain sensitive information from process heap memory**

* PLATFORMS: *AIX 5.3, 6.1 and 7.1, VIOS 2.2*
* SOLUTION: *Apply the fix as described below.*
* THREAT: *See below*
* CVE Numbers: *CVE-2014-9423*
* Reboot required? *NO*
* Workarounds? *NO*
* Protected by FPM? *NO*
* Protected by SED? *NO*

# DETAILED INFORMATION

## I. DESCRIPTION

1. **CVE-2014-5352**

   Security context handles are not properly maintained, which allows remote authenticated users to cause a denial of service(use-after-free and double free, and daemon crash) or possibly execute arbitrary code via crafted GSSAPI traffic.

2. **CVE-2014-5355**

   A remote attackers can cause a denial of service (NULL pointer dereference) via a zero-byte version string or  cause a denial of service(out-of-bounds read) by omitting the '\0' character.

3. **CVE-2014-9421**

   Remote authenticated users can cause a denial of service (use-after-free and double free, and daemon crash) or possibly execute arbitrary code via malformed XDR data.

4. **CVE-2014-9422**

   A remote authenticated users can obtain administrative access by leveraging access to a two-component principal with an initial "kadmind" substring.

5. **CVE-2014-9423**

   A remote attackers can obtain sensitive information from process heap memory by sniffing the network for data in a handle field

## II. CVSS

1. **CVE-2014-5352**
   * CVSS Base Score: 9.0
   * CVSS Temporal Score: https://exchange.xforce.ibmcloud.com/vulnerabilities/100842
   * CVSS Environmental Score: Undefined
   * CVSS Vector: (AV:N/AC:L/Au:S/C:C/I:C/A:C)

2. **CVE-2014-5355**
   * CVSS Base Score: 5.0
   * CVSS Temporal Score: https://exchange.xforce.ibmcloud.com/vulnerabilities/100972
   * CVSS Environmental Score: Undefined
   * CVSS Vector: (AV:N/AC:L/Au:N/C:N/I:N/A:P)

3. **CVE-2014-9421**
   * CVSS Base Score: 9.0
   * CVSS Temporal Score: https://exchange.xforce.ibmcloud.com/vulnerabilities/100841
   * CVSS Environmental Score: Undefined
   * CVSS Vector: (AV:N/AC:L/Au:S/C:C/I:C/A:C)

4. **CVE-2014-9422**
   * CVSS Base Score: 6.1
   * CVSS Temporal Score: https://exchange.xforce.ibmcloud.com/vulnerabilities/100840
   * CVSS Environmental Score: Undefined
   * CVSS Vector: (AV:N/AC:H/Au:S/C:P/I:P/A:C)

5. **CVE-2014-9423**
   * CVSS Base Score: 5.0
   * CVSS Temporal Score: https://exchange.xforce.ibmcloud.com/vulnerabilities/100839
   * CVSS Environmental Score: Undefined
   * CVSS Vector: (AV:N/AC:L/Au:N/C:P/I:N/A:N)

## III. PLATFORM VULNERABILITY ASSESSMENT

To determine if your system is vulnerable, execute the following command to obtain the NAS fileset level:

    lslpp -L krb5.client.rte
    lslpp -L krb5.server.rte

The following fileset levels are vulnerable:

| AIX Fileset | Lower Level | Upper Level |
| ----------- |  ---------- | ----------- |
| krb5.client.rte | 1.4.0.8 | 1.6.0.2 |
| krb5.server.rte | 1.4.0.8 | 1.6.0.2 |

Note, 1.4.0.8 is the Lowest NAS version available in aix web download site. Even NAS version below this are impacted

## IV. SOLUTIONS

### A. FIXES

Fix is available. The fix can be downloaded via ftp from: <ftp://aix.software.ibm.com/aix/efixes/security/nas3_fix.tar>

The above link is to a tar file containing this signed advisory, fix packages, and OpenSSL signatures for each package.

The fixes below include prerequisite checking.  This will enforce the correct mapping between the fixes and AIX releases.

The tar file contains Interim fixes that are based on NAS fileset levels.

#### AIX Level 5.3, 6.1, 7.1 and VIOS Level 2.2.*

If the NAS fileset level is at 1.5.0.7 then apply the ifix -

* `1507c_fix.150404.epkg.Z` if only `krb5.client.rte` is installed
* `1507s_fix.150407.epkg.Z` if `krb5.server.rte` is installed

If the NAS fileset level is at 1.6.0.2 then apply the ifix -

* `1602c_fix.150404.epkg.Z` if only `krb5.client.rte` is installed
* `1602s_fix.150407.epkg.Z` if `krb5.server.rte` is installed

If the NAS fileset level is at 1.5.0.3/1.5.0.4, then upgrade to fileset level 1.6.0.2 and apply the ifix -
* `1602c_fix.150404.epkg.Z` if only `krb5.client.rte` is installed
* `1602s_fix.150407.epkg.Z` if `krb5.server.rte` is installed

For other fileset level, upgrade to fileset level 1.5.0.7 and apply the ifix -
* `1507c_fix.150404.epkg.Z` if only `krb5.client.rte` is installed
* `1507s_fix.150407.epkg.Z` if `krb5.server.rte` is installed

To extract the fix from the tar file:

    tar xvf nas3_fix.tar
    cd nas3_fix

Verify you have retrieved the fix intact:

The checksums below were generated using the ``openssl dgst -sha256 file`` command is the followng:

| openssl dgst -sha256 | filename |
| -------------------- | -------- |
| 4dc9f7af7f281d3b1b679230d7c957a107b0e14e471482ef86fbe2cff9a7672f | 1507c_fix.150404.epkg.Z |
| fc4a7c777630380294c1835cca32b438882bb503a94b6ce43761a728ac05152b | 1507s_fix.150407.epkg.Z |
| dd3356b711e822b5bd4599b4c327d047699cd492eed04d9d5b6c4d3042ef52e9 | 1602c_fix.150404.epkg.Z |
| a3ff287d83f05476ac64b72baebf17b69ffffc530c06ec44fb63b98359f332b6 | 1602s_fix.150407.epkg.Z |

These sums should match exactly. The OpenSSL signatures in the tar file and on this advisory
can also be used to verify the integrity of the fixes.  If the sums or signatures cannot be confirmed, contact IBM AIX Security at <security-alert@austin.ibm.com> and describe the discrepancy.

Published advisory OpenSSL signature file location:

* <http://aix.software.ibm.com/aix/efixes/security/nas_advisory3.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/nas_advisory3.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/nas_advisory13.asc.sig>

```
    openssl dgst -sha1 -verify <pubkey_file> -signature <advisory_file>.sig <advisory_file>
    openssl dgst -sha1 -verify <pubkey_file> -signature <ifix_file>.sig <ifix_file>
```

### B. FIX AND INTERIM FIX INSTALLATION

*IMPORTANT*: If possible, it is recommended that a mksysb backup of the system be created.
Verify it is both bootable and readable before proceeding.

To preview a fix installation:

    installp -a -d fix_name -p all  # where fix_name is the name of the
                                    # fix package being previewed.

To install a fix package:

    installp -a -d fix_name -X all  # where fix_name is the name of the
                                    # fix package being installed.

Interim fixes have had limited functional and regression
testing but not the full regression testing that takes place
for Service Packs; however, IBM does fully support them.

Interim fix management documentation can be found at: http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html

To preview an interim fix installation:

    emgr -e ipkg_name -p         # where ipkg_name is the name of the
                                 # interim fix package being previewed.

To install an interim fix package:

    emgr -e ipkg_name -X         # where ipkg_name is the name of the
                                 # interim fix package being installed.

## V. WORKAROUNDS

No workarounds.

## VI. CONTACT INFORMATION

If you would like to receive AIX Security Advisories via email, please visit: http://www.ibm.com/systems/support
and click on the "My notifications" link.

To view previously issued advisories, please visit: http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq

Comments regarding the content of this announcement can be directed to: <security-alert@austin.ibm.com>

To obtain the OpenSSL public key that can be used to verify the signed advisories and ifixes:

Download the key from our web page: http://www.ibm.com/systems/resources/systems_p_os_aix_security_pgpkey.txt

To obtain the PGP public key that can be used to communicate
securely with the AIX Security Team you can either:

* A. Send an email with "get key" in the subject line to: <security-alert@austin.ibm.com>
* B. Download the key from a PGP Public Key Server. The key ID is: 0x28BFAA12

Please contact your local IBM AIX support center for any assistance.  

## VII. REFERENCES:

Note: Keywords labeled as KEY in this document are used for parsing purposes.

eServer is a trademark of International Business Machines Corporation.

IBM, AIX and pSeries are registered trademarks of International Business Machines Corporation.

All other trademarks are property of their respective holders.

Complete CVSS Guide: http://www.first.org/cvss/cvss-guide.html

On-line Calculator V2: http://nvd.nist.gov/cvss.cfm?calculator&adv&version=2

CVE-2014-5352 : http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5352

CVE-2014-5355 : http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5355

CVE-2014-9421 : http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9421

CVE-2014-9422 : http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9422

CVE-2014-9423 : http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9423

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

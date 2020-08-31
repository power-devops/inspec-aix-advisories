# IBM SECURITY ADVISORY

First Issued: Fri Aug 21 15:48:15 CDT 2020

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/bind_advisory17.asc>
* <https://aix.software.ibm.com/aix/efixes/security/bind_advisory17.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/bind_advisory17.asc>

Security Bulletin: Vulnerabilities in BIND affect AIX (CVE-2020-8616 and CVE-2020-8617)

# SUMMARY

There are vulnerabilities in BIND that affect AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2020-8616
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8616>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8616>
* *DESCRIPTION* 
  ISC BIND is vulnerable to a denial of service, caused by the
  failure to limit the number of fetches performed when processing
  referrals. By using specially crafted referrals, a remote attacker
  could exploit this vulnerability to cause the recursing server to
  issue a very large number of fetches in an attempt to process the
  referral.
* CVSS Base Score: 8.6
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/182126> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H)

## CVEID: CVE-2020-8617
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8617>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8617>
* *DESCRIPTION*
  ISC BIND is vulnerable to a denial of service, caused by a
  logic error in code which checks TSIG validity. A remote attacker
  could exploit this vulnerability to trigger an assertion failure in
  tsig.c.
* CVSS Base Score: 7.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/182127> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

# AFFECTED PRODUCTS AND VERSIONS
 
* AIX 7.1, 7.2
* VIOS 2.2, 3.1

The following fileset levels are vulnerable:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.client | 6.1.9.0 | 6.1.9.404 | key_w_fs |
| bos.net.tcp.client | 7.1.5.0 | 7.1.5.35 | key_w_fs |
| bos.net.tcp.bind_utils | 7.2.2.0 | 7.2.2.18 | key_w_fs |
| bos.net.tcp.bind_utils | 7.2.3.0 | 7.2.3.16 | key_w_fs |
| bos.net.tcp.bind_utils | 7.2.4.0 | 7.2.4.1 | key_w_fs |
        
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

```
lslpp -L | grep -i bos.net.tcp.client
```

# REMEDIATION:

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 7.1.5 | IJ25924 | ** | SP07-2037 | key_w_apar |
| 7.2.2 | IJ25925 | ** | N/A | key_w_apar |
| 7.2.3 | IJ25926 | ** | SP06-2038 | key_w_apar |
| 7.2.4 | IJ25927 | ** | SP03-2038 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.6 | IJ26021 | ** | N/A | key_w_apar |
| 3.1.0 | IJ25926 | ** | 3.1.0.50 | key_w_apar |
| 3.1.1 | IJ25927 | ** | 3.1.1.30 | key_w_apar |

Subscribe to the APARs here:

* <http://www.ibm.com/support/pages/apar/IJ25924>
* <http://www.ibm.com/support/pages/apar/IJ25925>
* <http://www.ibm.com/support/pages/apar/IJ25926>
* <http://www.ibm.com/support/pages/apar/IJ25927>
* <http://www.ibm.com/support/pages/apar/IJ26021>

* <https://www.ibm.com/support/pages/apar/IJ25924>
* <https://www.ibm.com/support/pages/apar/IJ25925>
* <https://www.ibm.com/support/pages/apar/IJ25926>
* <https://www.ibm.com/support/pages/apar/IJ25927>
* <https://www.ibm.com/support/pages/apar/IJ26021>

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX and VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/bind_fix17.tar>
* <http://aix.software.ibm.com/aix/efixes/security/bind_fix17.tar>
* <https://aix.software.ibm.com/aix/efixes/security/bind_fix17.tar>

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

| AIX Level | Interim Fix (\*.Z) | KEY |
| --------- | ----------------- | --- |
| 7.1.5.4 | IJ25924s6a.200708.epkg.Z | key_w_fix |
| 7.1.5.5 | IJ25924s6a.200708.epkg.Z | key_w_fix |
| 7.1.5.6 | IJ25924s6a.200708.epkg.Z | key_w_fix |
| 7.2.2.4 | IJ25925s6a.200708.epkg.Z | key_w_fix |
| 7.2.2.5 | IJ25925s6a.200708.epkg.Z | key_w_fix |
| 7.2.2.6 | IJ25925s6a.200708.epkg.Z | key_w_fix |
| 7.2.3.3 | IJ25926s5a.200708.epkg.Z | key_w_fix |
| 7.2.3.4 | IJ25926s5a.200708.epkg.Z | key_w_fix |
| 7.2.3.5 | IJ25926s5a.200708.epkg.Z | key_w_fix |
| 7.2.4.0 | IJ25927s2a.200708.epkg.Z | key_w_fix |
| 7.2.4.1 | IJ25927s2a.200708.epkg.Z | key_w_fix |
| 7.2.4.2 | IJ25927s2a.200708.epkg.Z | key_w_fix |
    
Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.3.5 is AIX 7200-03-05.

Please reference the Affected Products and Version section above
for help with checking installed fileset levels.

| VIOS Level | Interim Fix (\*.Z) | KEY | 
| ---------- | ------------------ | --- |
| 2.2.6.40 | IJ26021sDa.200708.epkg.Z | key_w_fix |
| 2.2.6.41 | IJ26021sDa.200708.epkg.Z | key_w_fix |
| 2.2.6.50 | IJ26021sDa.200708.epkg.Z | key_w_fix |
| 2.2.6.51 | IJ26021sDa.200708.epkg.Z | key_w_fix |
| 2.2.6.60 | IJ26021sDa.200708.epkg.Z | key_w_fix |
| 2.2.6.61 | IJ26021sDa.200708.epkg.Z | key_w_fix |
| 2.2.6.65 | IJ26021sDa.200708.epkg.Z | key_w_fix |
| 3.1.0.20 | IJ25926s5a.200708.epkg.Z | key_w_fix |
| 3.1.0.30 | IJ25926s5a.200708.epkg.Z | key_w_fix |
| 3.1.0.40 | IJ25926s5a.200708.epkg.Z | key_w_fix |
| 3.1.1.0 | IJ25927s2a.200708.epkg.Z | key_w_fix |
| 3.1.1.10 | IJ25927s2a.200708.epkg.Z | key_w_fix |
| 3.1.1.20 | IJ25927s2a.200708.epkg.Z | key_w_fix |
| 3.1.1.21 | IJ25927s2a.200708.epkg.Z | key_w_fix |
| 3.1.1.22 | IJ25927s2a.200708.epkg.Z | key_w_fix |
| 3.1.1.25 | IJ25927s2a.200708.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
tar xvf bind_fix17.tar
cd bind_fix17
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 [filename]` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 1b952357d1691d203c13d888760553743269a7b84e3432131bab9a6a919a53a7 | IJ25924s6a.200708.epkg.Z | key_w_csum |
| 5f221cb2ee211f02256d5e88c8a5962aed7a97ae6683a6eaf3724fe81eef0fe8 | IJ25925s6a.200708.epkg.Z | key_w_csum |
| e9b46105c1713fc1944b55fd3d637d912feaec439865bcc23a91c8f739ea5535 | IJ25926s5a.200708.epkg.Z | key_w_csum |
| d8a02e72780156eca420977627bb7c80455afc6e4b3d40a0e5cb5c6a72c4cfaa | IJ25927s2a.200708.epkg.Z | key_w_csum |
| 974e499efc70808300e1e7bb7af7706765a6ccd040c5e76944a52b727c0f5dd7 | IJ26021sDa.200708.epkg.Z | key_w_csum |


These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at
<http://ibm.com/support/> and describe the discrepancy.         
 
 ```
openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
 
openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/bind_advisory17.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/bind_advisory17.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/bind_advisory17.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

If possible, it is recommended that a mksysb backup of the system 
be created. Verify it is both bootable and readable before
proceeding.

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

If you would like to receive AIX Security Advisories via email,
please visit "My Notifications":

* <http://www.ibm.com/support/mynotifications>

To view previously issued advisories, please visit:

* <http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>
 
Contact IBM Support for questions related to this announcement:

* <http://ibm.com/support/>
* <https://ibm.com/support/>

To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page:

* <ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

# REFERENCES
 
* Complete CVSS v3 Guide:  <http://www.first.org/cvss/user-guide>
* On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>

# RELATED INFORMATION

* IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>
* IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>
* Security Bulletin: Vulnerabilities in BIND affect AIX <https://www.ibm.com/support/pages/node/6320325>

# ACKNOWLEDGEMENTS

None.

# CHANGE HISTORY

First Issued: Fri Aug 21 15:48:15 CDT 2020

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


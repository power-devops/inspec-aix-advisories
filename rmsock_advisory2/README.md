# IBM SECURITY ADVISORY

* First Issued: Thu Jun 21 14:07:15 CDT 2018
* Updated: Tue Jul  3 08:09:45 CDT 2018
* Update: Additional iFixes are now available. Additional iFixes are now available for:
  * AIX 6100-09-09 and 6100-09-10
  * AIX 7100-04-04 and 7100-04-05
  * AIX 7100-05-00 and 7100-05-01
  * AIX 7200-00-04 and 7200-00-05
  * AIX 7200-01-02 and 7200-01-03
  * AIX 7200-02-00 and 7200-02-01
  * VIOS 2.2.4.40, 2.2.4.50, and 2.2.4.60
  * VIOS 2.2.5.20, 2.2.5.30, and 2.2.5.40
  * VIOS 2.2.6.10

The most recent version of this document is available here:
* <http://aix.software.ibm.com/aix/efixes/security/rmsock_advisory2.asc>
* <https://aix.software.ibm.com/aix/efixes/security/rmsock_advisory2.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/rmsock_advisory2.asc>

Security Bulletin: Vulnerability in rmsock affects AIX (CVE-2018-1655) 

# SUMMARY

There is a vulnerability in the rmsock command that affects AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2018-1655
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1655>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1655>
* **DESCRIPTION**
  IBM AIX contains a vulnerability in the rmsock command that 
  may be used to expose kernel memory.
* CVSS Base Score: 4
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/144748 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)


# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x 

The vulnerabilities in the following filesets are being addressed:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.client | 5.3.12.0 | 5.3.12.10 | key_w_fs |
| bos.net.tcp.client | 6.1.9.0 | 6.1.9.315 | key_w_fs |
| bos.net.tcp.client | 7.1.4.0 | 7.1.4.33 | key_w_fs |
| bos.net.tcp.client | 7.1.5.0 | 7.1.5.15 | key_w_fs |
| bos.net.tcp.client_core | 7.2.0.0 | 7.2.0.5 | key_w_fs |
| bos.net.tcp.client_core | 7.2.1.0 | 7.2.1.3 | key_w_fs |
| bos.net.tcp.client_core | 7.2.2.0 | 7.2.2.16 | key_w_fs |

To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

    lslpp -L | grep -i bos.net.tcp.client

Note: AIX or VIOS users of all fileset levels should continue to monitor
their My Notifications alerts and the IBM PSIRT Blog for additional 
information about these vulnerabilities:

- My Notifications http://www.ibm.com/support/mynotifications


# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 5.3.12 | IJ06935 | ** | N/A | key_w_apar |
| 6.1.9 | IJ06905 | ** | SP12 | key_w_apar |
| 7.1.4 | IJ06906 | ** | SP7 | key_w_apar |
| 7.1.5 | IJ06904 | ** | SP3 | key_w_apar |
| 7.2.0 | IJ06934 | ** | N/A | key_w_apar |
| 7.2.1 | IJ06907 | ** | SP5 | key_w_apar |
| 7.2.2 | IJ06908 | ** | SP3 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.4 | IJ06905 | ** | N/A | key_w_apar |
| 2.2.5 | IJ06905 | ** | 2.2.5.50 | key_w_apar |
| 2.2.6 | IJ06905 | ** | 2.2.6.30 | key_w_apar |

Subscribe to the APARs here:

* http://www.ibm.com/support/docview.wss?uid=isg1IJ06904
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06905
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06906
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06907
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06908
* http://www.ibm.com/support/docview.wss?uid=isg1IJ06934

* https://www.ibm.com/support/docview.wss?uid=isg1IJ06904
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06905
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06906
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06907
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06908
* https://www.ibm.com/support/docview.wss?uid=isg1IJ06934

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX/VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/rmsock_fix2.tar>
* <http://aix.software.ibm.com/aix/efixes/security/rmsock_fix2.tar>
* <https://aix.software.ibm.com/aix/efixes/security/rmsock_fix2.tar>

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.
            
| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 5.3.12.9 | IJ06935s1a.180611.epkg.Z | key_w_fix |
| 6.1.9.9 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 6.1.9.10 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 6.1.9.11 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 7.1.4.4 | IJ06906s4a.180607.epkg.Z | key_w_fix |
| 7.1.4.5 | IJ06906s4a.180607.epkg.Z | key_w_fix |
| 7.1.4.6 | IJ06906s4a.180607.epkg.Z | key_w_fix |
| 7.1.5.0 | IJ06904s5a.180607.epkg.Z | key_w_fix |
| 7.1.5.1 | IJ06904s5a.180607.epkg.Z | key_w_fix |
| 7.1.5.2 | IJ06904s5a.180607.epkg.Z | key_w_fix |
| 7.2.0.4 | IJ06934s0a.180607.epkg.Z | key_w_fix |
| 7.2.0.5 | IJ06934s0a.180607.epkg.Z | key_w_fix |
| 7.2.0.6 | IJ06934s0a.180607.epkg.Z | key_w_fix |
| 7.2.1.2 | IJ06907s1a.180607.epkg.Z | key_w_fix |
| 7.2.1.3 | IJ06907s1a.180607.epkg.Z | key_w_fix |
| 7.2.1.4 | IJ06907s1a.180607.epkg.Z | key_w_fix |
| 7.2.2.0 | IJ06908s2a.180607.epkg.Z | key_w_fix |
| 7.2.2.1 | IJ06908s2a.180607.epkg.Z | key_w_fix |
| 7.2.2.2 | IJ06908s2a.180607.epkg.Z | key_w_fix |

Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.2 is AIX 7200-02-02.


| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.4.40 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.4.50 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.4.60 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.5.20 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.5.30 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.5.40 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.6.10 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.6.20 | IJ06905s9a.180608.epkg.Z | key_w_fix |
| 2.2.6.21 | IJ06905s9a.180608.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
    tar xvf rmsock_fix2.tar 
    cd rmsock_fix2
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 file` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| ecf6f66a7b4b46d409d793f20040ee482483b1574171fb9359a923dd4895ab1a | IJ06904s5a.180607.epkg.Z | key_w_csum |
| c3c126553e839d9005e57b9c86c64ee9ec6bbaf2ab9a11a1999c5e513a27169c | IJ06905s9a.180608.epkg.Z | key_w_csum |
| c9853fd282018e3d4a7f43d7be2bdb8683e0b6fcafa030b0da3066071714a58b | IJ06906s4a.180607.epkg.Z | key_w_csum |
| d315a1422bad889b916b05bedd3f7a2017a6fd0cec92102bf82a4ae29097778e | IJ06907s1a.180607.epkg.Z | key_w_csum |
| 1cf55bf5ba872df48e210a65d5d0830f08cff0173dc5cc6570be7b6a02268241 | IJ06908s2a.180607.epkg.Z | key_w_csum |
| b9ff613c66d80bb855808e2ef94a67d5643fd7587b134dc6a5619ac708c3a8d0 | IJ06934s0a.180607.epkg.Z | key_w_csum |
| 1403b64ca4a545ef791460764a184d5a48a7112daec235474f070c5ff569e6cd | IJ06935s1a.180611.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at
http://ibm.com/support/ and describe the discrepancy.         
 
```
            openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
 
            openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/rmsock_advisory2.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/rmsock_advisory2.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/rmsock_advisory2.asc.sig>

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

http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html

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

http://www.ibm.com/support/mynotifications

To view previously issued advisories, please visit:

http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq
 
Contact IBM Support for questions related to this announcement:

* http://ibm.com/support/
* https://ibm.com/support/

To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page:

http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt

Please contact your local IBM AIX support center for any assistance.


# REFERENCES
 
* Complete CVSS v3 Guide:  http://www.first.org/cvss/user-guide
* On-line Calculator v3: http://www.first.org/cvss/calculator/3.0


# RELATED INFORMATION

IBM Secure Engineering Web Portal http://www.ibm.com/security/secure-engineering/bulletins.html

IBM Product Security Incident Response Blog https://www.ibm.com/blogs/psirt/

Security Bulletin: Vulnerability in rmsock affects AIX (CVE-2018-1655) http://www-01.ibm.com/support/docview.wss?uid=isg3T1027880

# ACKNOWLEDGEMENTS

The vulnerability was reported to IBM by Tim Brown, Security Advisor EMEAR, Cisco..


# CHANGE HISTORY

* First Issued: Thu Jun 21 14:07:15 CDT 2018
* Updated: Tue Jul  3 08:09:45 CDT 2018
* Update: Additional iFixes are now available. Additional iFixes are now available for:
  * AIX 6100-09-09 and 6100-09-10
  * AIX 7100-04-04 and 7100-04-05
  * AIX 7100-05-00 and 7100-05-01
  * AIX 7200-00-04 and 7200-00-05
  * AIX 7200-01-02 and 7200-01-03
  * AIX 7200-02-00 and 7200-02-01
  * VIOS 2.2.4.40, 2.2.4.50, and 2.2.4.60
  * VIOS 2.2.5.20, 2.2.5.30, and 2.2.5.40
  * VIOS 2.2.6.10


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






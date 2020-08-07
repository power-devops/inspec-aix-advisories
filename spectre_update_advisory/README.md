# IBM SECURITY ADVISORY

First Issued: Fri Aug 17 08:05:01 CDT 2018

The most recent version of this document is available here:

<http://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc>

<https://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc>

<ftp://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc>

Security Bulletin: IBM has released updated AIX and VIOS fixes for  
CVE-2017-5715, known as Spectre, that are only applicable to some POWER9 
systems.

# SUMMARY

IBM has released updated AIX and VIOS fixes for CVE-2017-5715, known as 
Spectre, that are only applicable to the following POWER9 systems:

9040-MR9

The prtconf command may be used to find the system model number.
For example:  `prtconf | grep "System Model"`


# VULNERABILITY DETAILS

## CVEID: CVE-2017-5715

* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715>

## AFFECTED PRODUCTS AND VERSIONS
 
* AIX 6.1, 7.1, 7.2
* VIOS 2.2.x 

The vulnerabilities in the following filesets are being addressed:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.mp64 | 6.1.9.0 | 6.1.9.316 | key_w_fs |
| bos.mp64 | 7.1.4.0 | 7.1.4.34 | key_w_fs |
| bos.mp64 | 7.1.5.0 | 7.1.5.16 | key_w_fs |
| bos.mp64 | 7.2.1.0 | 7.2.1.5 | key_w_fs |
| bos.mp64 | 7.2.2.0 | 7.2.2.16 | key_w_fs |
        
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

    lslpp -L | grep -i bos.mp64


# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 6.1.9 | IJ07498 | ** | SP12 | key_w_apar |
| 7.1.4 | IJ07499 | ** | SP7 | key_w_apar |
| 7.1.5 | IJ07500 | ** | SP3 | key_w_apar |
| 7.2.1 | IJ07501 | ** | SP5 | key_w_apar |
| 7.2.2 | IJ07497 | ** | SP3 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.4 | IJ07498 | ** | N/A | key_w_apar |
| 2.2.5 | IJ07498 | ** | 2.2.5.50 | key_w_apar |
| 2.2.6 | IJ07498 | ** | 2.2.6.23 | key_w_apar |

The relevant APARs will also be included in 7.1.5 and
7.2.2 SPs with a build id of 1832 or later.

Subscribe to the APARs here:

* <http://www.ibm.com/support/docview.wss?uid=isg1IJ07497>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ07498>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ07499>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ07500>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ07501>

* <https://www.ibm.com/support/docview.wss?uid=isg1IJ07497>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ07498>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ07499>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ07500>

* <https://www.ibm.com/support/docview.wss?uid=isg1IJ07501>

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

An LPAR system reboot is required to complete the iFix installation,
or Live Update may be used on AIX 7.2 to avoid a reboot.

The AIX and VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/spectre_update_fix.tar>
* <http://aix.software.ibm.com/aix/efixes/security/spectre_update_fix.tar>
* <https://aix.software.ibm.com/aix/efixes/security/spectre_update_fix.tar>

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

The provided fixes are cumulative and include the previously issued
Spectre and Meltdown (CVE-2017-5715, CVE-2017-5753, and CVE-2017-5754) 
security fixes:

<http://aix.software.ibm.com/aix/efixes/security/spectre_meltdown_advisory.asc>

and Variant 4 (CVE-2018-3639) security fixes:

<http://aix.software.ibm.com/aix/efixes/security/variant4_advisory.asc>
            
| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 6.1.9.9 | IJ07498m9a.180726.epkg.Z | key_w_fix |
| 6.1.9.10 | IJ07498mAa.180717.epkg.Z | key_w_fix |
| 6.1.9.11 | IJ07498mBa.180713.epkg.Z | key_w_fix |
| 7.1.4.4 | IJ07499m4a.180719.epkg.Z | key_w_fix |
| 7.1.4.5 | IJ07499m5a.180809.epkg.Z | key_w_fix |
| 7.1.4.6 | IJ07499m6a.180713.epkg.Z | key_w_fix |
| 7.1.5.1 | IJ07500m1a.180718.epkg.Z | key_w_fix |
| 7.1.5.2 | IJ07500m2a.180713.epkg.Z | key_w_fix |
| 7.2.1.2 | IJ07501m2a.180719.epkg.Z | key_w_fix |
| 7.2.1.3 | IJ07501m3a.180717.epkg.Z | key_w_fix |
| 7.2.1.4 | IJ07501m4a.180716.epkg.Z | key_w_fix |
| 7.2.2.1 | IJ07497m1a.180717.epkg.Z | key_w_fix |
| 7.2.2.2 | IJ07497m2a.180713.epkg.Z | key_w_fix |
 
Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.1 is AIX 7200-02-01.
 
The provided iFixes for 7.1.5.2 and 7.2.2.2 are not required on SPs 
with a build id of 1832 or later. Please run "oslevel -s" to view 
installed build id.

Please reference the Affected Products and Version section above
for help with checking installed fileset levels.

| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.4.40 | IJ07498m9a.180726.epkg.Z | key_w_fix |
| 2.2.4.50 | IJ07498m9b.180726.epkg.Z | key_w_fix |
| 2.2.4.60 | IJ07498mBa.180713.epkg.Z | key_w_fix |
| 2.2.5.20 | IJ07498m9a.180726.epkg.Z | key_w_fix |
| 2.2.5.30 | IJ07498m9b.180726.epkg.Z | key_w_fix |
| 2.2.5.40 | IJ07498mBa.180713.epkg.Z | key_w_fix |
| 2.2.6.0 | IJ07498mAa.180717.epkg.Z | key_w_fix |
| 2.2.6.10 | IJ07498mAa.180717.epkg.Z | key_w_fix |
| 2.2.6.20 | IJ07498mBa.180713.epkg.Z | key_w_fix |
| 2.2.6.21 | IJ07498mBa.180713.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
    tar xvf spectre_update_fix.tar
    cd spectre_update_fix
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 [filename]` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 8130c2fe38bc00ec0ffc40fb0ba807c576774255640ac91c3cf544a5186969e5 | IJ07497m1a.180717.epkg.Z | key_w_csum |
| 489aa881e49d63814160bf9b685a8a55c667bb4f1ec8afb4134393a5a3d06093 | IJ07497m2a.180713.epkg.Z | key_w_csum |
| a97311134ec01ca205e0121576b05143b15718f2c3196dad08185b0ff56ff8dc | IJ07498m9a.180726.epkg.Z | key_w_csum |
| c34866b7148bfd7eacf203d3fd038f6edc138330b9329222ca1f884d22e74fa0 | IJ07498m9b.180726.epkg.Z | key_w_csum |
| a3033670dcd28502594243789d646edc036c89c549b80e9b41468ec688222195 | IJ07498mAa.180717.epkg.Z | key_w_csum |
| 4dc17657d5d7ccf59876cd9e60a041ab45495e683e46bca0e6a978143d9f9b04 | IJ07498mBa.180713.epkg.Z | key_w_csum |
| 8e5df1d36261b795985d6da09549cc4b2b7f09a57352a8aa2990a2e65b6ef0cf | IJ07499m4a.180719.epkg.Z | key_w_csum |
| 6d7e31ce2db7c26b0095258fb0e7067cdb5eea6815f2ed89e7df5db2f888fd15 | IJ07499m5a.180809.epkg.Z | key_w_csum |
| 19e901819690cc66094a50a69b89874db2f7dd622f2b20342434a73c06b0d813 | IJ07499m6a.180713.epkg.Z | key_w_csum |
| c0a9110911d9f030e9a8da174d19bd25e25dfc748689908d460d7b6da3c0f96b | IJ07500m1a.180718.epkg.Z | key_w_csum |
| 79328878b1463a849ba402ec94c5dabe84d23b1d68e1bb2003bfad2cf91c7bca | IJ07500m2a.180713.epkg.Z | key_w_csum |
| dd2c1125dcd39242eae5e8c599099be65530b477964157f677f824e5bb748ee0 | IJ07501m2a.180719.epkg.Z | key_w_csum |
| 0f85af1fb54a8f3b948283a994a024471c6613a4f5375d2c9105704adf448b4e | IJ07501m3a.180717.epkg.Z | key_w_csum |
| dd9c82da0afe7cc6cd2dedf241dde09c94d92307aff8372fd4bd352e1b353221 | IJ07501m4a.180716.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at
http://ibm.com/support/ and describe the discrepancy.         
 

    openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
    openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

An LPAR system reboot is required to complete the iFix installation,
or Live Update may be used on AIX 7.2 to avoid a reboot.

If possible, it is recommended that a mksysb backup of the system 
be created. Verify it is both bootable and readable before
proceeding.

To preview a fix installation:

    installp -a -d fix_name -p all  # where fix_name is the name of the
                                    # fix package being previewed.

To install a fix package:

    installp -a -d fix_name -X all  # where fix_name is the name of the
                                    # fix package being installed.

Interim fixes have had limited functional and regression
testing but not the full regression testing that takes place
for Service Packs; however, IBM does fully support them.

Interim fix management documentation can be found at:

<http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html>

To preview an interim fix installation:

    emgr -e ipkg_name -p         # where ipkg_name is the name of the
                                 # interim fix package being previewed.

To install an interim fix package:

    emgr -e ipkg_name -X         # where ipkg_name is the name of the
                                 # interim fix package being installed.

# WORKAROUNDS AND MITIGATIONS:

None.

# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing
purposes.

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

<ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.


# REFERENCES
 
* Complete CVSS v3 Guide:  <http://www.first.org/cvss/user-guide>
* On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

* IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>
* IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>
* IBM PSIRT Blog - Potential Impact on Processors in the Power Family <https://www.ibm.com/blogs/psirt/potential-impact-processors-power-family/>

Security Bulletin: IBM has released updated AIX and VIOS fixes for 
CVE-2017-5715, known as Spectre, that are only applicable to some POWER9 
systems.

<https://www-01.ibm.com/support/docview.wss?uid=ibm10719541>

# ACKNOWLEDGEMENTS

The vulnerability was reported to IBM by Google Project Zero.


# CHANGE HISTORY

First Issued: Fri Aug 17 08:05:01 CDT 2018


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




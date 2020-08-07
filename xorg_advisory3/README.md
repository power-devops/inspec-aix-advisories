# IBM SECURITY ADVISORY

* First Issued: Tue Dec 11 09:32:52 CST 2018
* Updated: Mon Dec 17 08:33:34 CST 2018
* Update: Corrected the iFixes listed for AIX 7100-05.
* Updated: Tue Apr  9 09:52:17 CDT 2019
* Update: Added AIX 7100-04-07 and 7200-02-03 as affected.
* Update: Added iFixes for AIX 7100-04-07 and 7200-02-03.

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/xorg_advisory3.asc>
* <https://aix.software.ibm.com/aix/efixes/security/xorg_advisory3.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/xorg_advisory3.asc>

Security Bulletin: Vulnerability in Xorg affects AIX (CVE-2018-14665)

# SUMMARY

There is a vulnerability in Xorg that affects AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2018-14665
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14665>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14665>
* **DESCRIPTION**
  X.Org X server could allow a remote authenticated attacker 
  to gain elevated privileges on the system, caused by improper 
  validation of command line parameters. An attacker could exploit this 
  vulnerability using the -modulepath argument or the -logfile argument 
  to overwrite arbitrary files and execute unprivileged code on the 
  system.
* CVSS Base Score: 8.8
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/151991 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)


# AFFECTED PRODUCTS AND VERSIONS
 
* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x 

The following fileset levels are vulnerable:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| X11.base.rte | 5.3.12.0 | 5.3.12.2 | key_w_fs |
| X11.base.rte | 6.1.9.0 | 6.1.9.100 | key_w_fs |
| X11.base.rte | 7.1.4.0 | 7.1.4.31 | key_w_fs |
| X11.base.rte | 7.1.5.0 | 7.1.5.31 | key_w_fs |
| X11.base.rte | 7.2.0.0 | 7.2.0.1 | key_w_fs |
| X11.base.rte | 7.2.1.0 | 7.2.1.0 | key_w_fs |
| X11.base.rte | 7.2.2.0 | 7.2.2.16 | key_w_fs |
| X11.base.rte | 7.2.3.0 | 7.2.3.15 | key_w_fs |
        
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

	lslpp -L | grep -i X11.base.rte


# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 5.3.12 | IJ11551 | ** | N/A | key_w_apar |
| 6.1.9 | IJ11000 | ** | N/A | key_w_apar |
| 7.1.4 | IJ11544 | ** | SP08 | key_w_apar |
| 7.1.5 | IJ11545 | ** | SP04 | key_w_apar |
| 7.2.0 | IJ11546 | ** | N/A | key_w_apar |
| 7.2.1 | IJ11547 | ** | SP06 | key_w_apar |
| 7.2.2 | IJ11549 | ** | SP04 | key_w_apar |
| 7.2.3 | IJ11550 | ** | SP03 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.4 | IJ11000 | ** | N/A | key_w_apar |
| 2.2.5 | IJ11000 | ** | 2.2.5.60 | key_w_apar |
| 2.2.6 | IJ11000 | ** | 2.2.6.40 | key_w_apar |
| 3.1.0 | IJ11550 | ** | 3.1.0.20 | key_w_apar |


Subscribe to the APARs here:

* http://www.ibm.com/support/docview.wss?uid=isg1IJ11000
* http://www.ibm.com/support/docview.wss?uid=isg1IJ11544
* http://www.ibm.com/support/docview.wss?uid=isg1IJ11545
* http://www.ibm.com/support/docview.wss?uid=isg1IJ11546
* http://www.ibm.com/support/docview.wss?uid=isg1IJ11547
* http://www.ibm.com/support/docview.wss?uid=isg1IJ11549
* http://www.ibm.com/support/docview.wss?uid=isg1IJ11550
* http://www.ibm.com/support/docview.wss?uid=isg1IJ11551

* https://www.ibm.com/support/docview.wss?uid=isg1IJ11000
* https://www.ibm.com/support/docview.wss?uid=isg1IJ11544
* https://www.ibm.com/support/docview.wss?uid=isg1IJ11545
* https://www.ibm.com/support/docview.wss?uid=isg1IJ11546
* https://www.ibm.com/support/docview.wss?uid=isg1IJ11547
* https://www.ibm.com/support/docview.wss?uid=isg1IJ11549
* https://www.ibm.com/support/docview.wss?uid=isg1IJ11550
* https://www.ibm.com/support/docview.wss?uid=isg1IJ11551

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX and VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/xorg_fix3.tar>
* <http://aix.software.ibm.com/aix/efixes/security/xorg_fix3.tar>
* <https://aix.software.ibm.com/aix/efixes/security/xorg_fix3.tar> 

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 5.3.12.x | IJ11551s0a.181127.epkg.Z | key_w_fix |
| 6.1.9.x | IJ11000s0b.181127.epkg.Z | key_w_fix |
| 7.1.4.x | IJ11544s0a.181127.epkg.Z | key_w_fix |
| 7.1.4.7 | IJ11544s0a.190312.epkg.Z | key_w_fix |
| 7.1.5.0 | IJ11544s0a.181127.epkg.Z | key_w_fix |
| 7.1.5.1 | IJ11544s0a.181127.epkg.Z | key_w_fix |
| 7.1.5.2 | IJ11544s0a.181127.epkg.Z | key_w_fix |
| 7.1.5.3 | IJ11544s0a.181127.epkg.Z | key_w_fix |
| 7.1.5.3 | IJ11545s0a.181127.epkg.Z | key_w_fix |
| 7.2.0.x | IJ11546s0a.181127.epkg.Z | key_w_fix |
| 7.2.1.x | IJ11547s0a.181127.epkg.Z | key_w_fix |
| 7.2.2.x | IJ11549s0a.181127.epkg.Z | key_w_fix |
| 7.2.2.3 | IJ11549s0a.190312.epkg.Z | key_w_fix |
| 7.2.3.x | IJ11550s0a.181127.epkg.Z | key_w_fix |

Please reference the Affected Products and Version section above
for help with checking installed fileset levels.

NOTE: Multiple iFixes are provided for AIX 7100-05-03.

* IJ11544s0a is for AIX 7100-05-03 with X11.base.rte fileset level 7.1.4.30.
* IJ11545s0a is for AIX 7100-05-03 with X11.base.rte fileset level 7.1.5.31.

| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.x | IJ11000s0b.181127.epkg.Z | key_w_fix |
| 3.1.x | IJ11550s0a.181127.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
            tar xvf xorg_fix3.tar
            cd xorg_fix3
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 [filename]` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 81a407e154ab90e003135bf075f171b127d811e3a9177cb866d589ff2459ef19 | IJ11000s0b.181127.epkg.Z | key_w_csum |
| 458f8391ceabeedf418f54595ce9ef87d63a667369dc4a3112b8548bff80fb6d | IJ11544s0a.181127.epkg.Z | key_w_csum |
| 2b719e0b4d8bdcb89f97ffe1ecceccfbf0538cb2cdec66b8214eeae7c7b37958 | IJ11544s0a.190312.epkg.Z | key_w_csum |
| 041e1271b858211365025a4528c71f453c72405a1f0809128e0c70d49886a166 | IJ11545s0a.181127.epkg.Z | key_w_csum |
| 1f4f7a7ef34c7804464ccdc02f1a253ac373a9c66ee3144350b390509976cfad | IJ11546s0a.181127.epkg.Z | key_w_csum |
| 8aac56821f52600ee3158efa39e0bf697813712364b946c199fbb32dd1da9ce6 | IJ11547s0a.181127.epkg.Z | key_w_csum |
| 7518d581224e6b4332b4cfab48253a7427fb0e3ab866567766b2d137bc0e9267 | IJ11549s0a.181127.epkg.Z | key_w_csum |
| f18e4f2efd4f488e7a02de90bfa6992b604298dba1d588689d4e58e71b3738db | IJ11550s0a.181127.epkg.Z | key_w_csum |
| 0eea9877dcaf6ffbd6c0d7572fd7ceb6437ef1f0b2f3134a22afc47260e9e7c5 | IJ11549s0a.190312.epkg.Z | key_w_csum |
| 190c800f4012e5c161dfe81425a30cfff55784cdc09097f73caa6320227f69c8 | IJ11551s0a.181127.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be confirmed, contact IBM Support at
http://ibm.com/support/ and describe the discrepancy.         
 
```
            openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
            openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/xorg_advisory3.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/xorg_advisory3.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/xorg_advisory3.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

If possible, it is recommended that a mksysb backup of the system be created. Verify it is both bootable and readable before
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

Interim fixes have had limited functional and regression testing but not the full regression testing that takes place
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

If you would like to receive AIX Security Advisories via email, please visit "My Notifications":

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

* Security Bulletin: Vulnerability in Xorg affects AIX (CVE-2018-14665) <https://www-01.ibm.com/support/docview.wss?uid=ibm10742279>

# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

* First Issued: Tue Dec 11 09:32:52 CST 2018
* Updated: Mon Dec 17 08:33:34 CST 2018
* Update: Corrected the iFixes listed for AIX 7100-05.
* Updated: Tue Apr  9 09:52:17 CDT 2019
* Update: Added AIX 7100-04-07 and 7200-02-03 as affected. Added iFixes for AIX 7100-04-07 and 7200-02-03.


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




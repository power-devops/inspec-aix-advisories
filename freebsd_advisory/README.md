# IBM SECURITY ADVISORY

* First Issued: Thu Nov  8 14:04:12 CST 2018
* Updated: Wed Dec  5 12:11:30 CST 2018
* Update: iFixes now provided for AIX 7200-03-02 and VIOS 2.2.6.32, 3.1.0.0,
and 3.1.0.10.

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/freebsd_advisory.asc>
* <https://aix.software.ibm.com/aix/efixes/security/freebsd_advisory.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/freebsd_advisory.asc>

Security Bulletin: Vulnerability in FreeBSD affects AIX (CVE-2018-6922)

# SUMMARY

There is a vulnerability in FreeBSD that affects AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2018-6922
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6922>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6922>
* **DESCRIPTION**
  FreeBSD is vulnerable to a denial of service, caused by the 
  use of an inefficient TCP reassembly algorithm. By sending 
  specially-crafted TCP traffic, a remote attacker could exploit this 
  vulnerability to consume all available CPU resources.
* CVSS Base Score: 7.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/148026> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)


## AFFECTED PRODUCTS AND VERSIONS
 
* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x 

The following fileset levels are vulnerable:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.rte | 5.3.12.0 | 5.3.12.1 | key_w_fs |
| bos.rte | 6.1.9.0 | 6.1.9.400 | key_w_fs |
| bos.rte | 7.1.4.0 | 7.1.4.32 | key_w_fs |
| bos.rte | 7.1.5.0 | 7.1.5.30 | key_w_fs |
| bos.rte | 7.2.0.0 | 7.2.0.3 | key_w_fs |
| bos.rte | 7.2.1.0 | 7.2.1.2 | key_w_fs |
| bos.rte | 7.2.2.0 | 7.2.2.15 | key_w_fs |
| bos.rte | 7.2.3.0 | 7.2.3.15 | key_w_fs |
        
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

```lslpp -L | grep -i bos.rte```

# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 5.3.12 | IJ09618 | ** | N/A | key_w_apar |
| 6.1.9 | IJ09619 | ** | N/A | key_w_apar |
| 7.1.4 | IJ09620 | ** | SP7 | key_w_apar |
| 7.1.5 | IJ09621 | ** | SP4 | key_w_apar |
| 7.2.0 | IJ09622 | ** | N/A | key_w_apar |
| 7.2.1 | IJ09623 | ** | SP5 | key_w_apar |
| 7.2.2 | IJ09624 | ** | SP3 | key_w_apar |
| 7.2.3 | IJ09625 | ** | SP3 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.4 | IJ09619 | ** | N/A | key_w_apar |
| 2.2.5 | IJ09619 | ** | 2.2.5.50 | key_w_apar |
| 2.2.6 | IJ09619 | ** | 2.2.6.40 | key_w_apar |
| 3.1.0 | IJ09625 | ** | 3.1.0.20 | key_w_apar |

Subscribe to the APARs here:

* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09618>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09619>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09620>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09621>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09622>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09623>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09624>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ09625>

* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09618>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09619>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09620>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09621>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09622>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09623>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09624>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ09625>

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

An LPAR system reboot is required to complete the iFix installation,
or Live Update may be used on AIX 7.2 to avoid a reboot.

The AIX and VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/freebsd_fix.tar>
* <http://aix.software.ibm.com/aix/efixes/security/freebsd_fix.tar>
* <https://aix.software.ibm.com/aix/efixes/security/freebsd_fix.tar>

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 5.3.12.9 | IJ09618s9a.181031.epkg.Z | key_w_fix |
| 6.1.9.10 |  IJ09619sAa.181004.epkg.Z | key_w_fix |
| 6.1.9.11 |  IJ09619sBa.181004.epkg.Z | key_w_fix |
| 6.1.9.12 |  IJ09619sCa.181009.epkg.Z | key_w_fix |
| 7.1.4.4 |   IJ09620s4a.180927.epkg.Z | key_w_fix |
| 7.1.4.5 |   IJ09620s5a.180927.epkg.Z | key_w_fix |
| 7.1.4.6 |   IJ09620s6a.180926.epkg.Z | key_w_fix |
| 7.1.5.1 |   IJ09621s1a.180926.epkg.Z | key_w_fix |
| 7.1.5.2 |   IJ09621s2a.180925.epkg.Z | key_w_fix |
| 7.1.5.3 |   IJ09621s3a.181001.epkg.Z | key_w_fix |
| 7.2.0.4 |   IJ09622s4a.181001.epkg.Z | key_w_fix |
| 7.2.0.5 |   IJ09622s5a.181001.epkg.Z | key_w_fix |
| 7.2.0.6 |   IJ09622s6a.181001.epkg.Z | key_w_fix |
| 7.2.1.2 |   IJ09623s2a.181002.epkg.Z | key_w_fix |
| 7.2.1.3 |   IJ09623s3a.181002.epkg.Z | key_w_fix |
| 7.2.1.4 |   IJ09623s4a.181002.epkg.Z | key_w_fix |
| 7.2.2.0 |   IJ09624s0a.181002.epkg.Z | key_w_fix |
| 7.2.2.1 |   IJ09624s1a.181003.epkg.Z | key_w_fix |
| 7.2.2.2 |   IJ09624s2a.181003.epkg.Z | key_w_fix |
| 7.2.3.0 |   IJ09625s0a.181010.epkg.Z | key_w_fix |
| 7.2.3.1 |   IJ09625s0a.181010.epkg.Z | key_w_fix |
| 7.2.3.2 | IJ09625s2a.181203.epkg.Z | key_w_fix |
    
Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.1 is AIX 7200-02-01.
 
Please reference the Affected Products and Version section above
for help with checking installed fileset levels.

| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.4.60 | IJ09619sBa.181004.epkg.Z | key_w_fix |
| 2.2.5.40 | IJ09619sBa.181004.epkg.Z | key_w_fix |
| 2.2.6.23 | IJ09619sBa.181004.epkg.Z | key_w_fix |
| 2.2.6.30 | IJ09619sCa.181009.epkg.Z | key_w_fix |
| 2.2.6.31 | IJ09619sCa.181009.epkg.Z | key_w_fix |
| 2.2.6.32 | IJ09619sCa.181009.epkg.Z | key_w_fix |
| 3.1.0.0 | IJ09625s2a.181203.epkg.Z | key_w_fix |
| 3.1.0.10 | IJ09625s2a.181203.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
tar xvf freebsd_fix.tar
cd freebsd_fix
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the ```openssl dgst -sha256 [filename]``` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| b5c7014035793e7f6be1282d60e8f41513acd3b812d3f698dead8e6a34c33836 | IJ09618s9a.181031.epkg.Z | key_w_csum |
| 05ae1d9525cf04571eb9d52ae48286c8e8b8563629cc5f025cf6bdc2a3c31bef | IJ09619sAa.181004.epkg.Z | key_w_csum |
| 60052520a6b91171433cc6775677561d7c4805922f5e71b9021567804cbf5839 | IJ09619sBa.181004.epkg.Z | key_w_csum |
| 61290b161399924a9ff401053ebd3b5ee653f0a08fb32af283320310ce8dc76b | IJ09619sCa.181009.epkg.Z | key_w_csum |
| 8d4148216457891428b8fcd110d94227dd9052a38e5bbc7ec1c489ef26b7ec41 | IJ09620s4a.180927.epkg.Z | key_w_csum |
| ed8fb402bcc5e61ed66dd93d17e4bdb495ca84f96df056cde8a51faccec1890b | IJ09620s5a.180927.epkg.Z | key_w_csum |
| 7775584ea7da80cd4cd8454cafbe3a942f6ec4e7952527905c9418d2d77a8614 | IJ09620s6a.180926.epkg.Z | key_w_csum |
| aa1ea66f3a99bd23ca0c66ce14b344ebebc0cfd693f03443f6d4b0003ce994f8 | IJ09621s1a.180926.epkg.Z | key_w_csum |
| a16276ac02280abc33df7edc338e7397a083a0e7cbdae2803f84d88338c0b542 | IJ09621s2a.180925.epkg.Z | key_w_csum |
| 12185b57e2168aa1e89ceba842f01ae0ecc0c66034f979461a74bb0453917a89 | IJ09621s3a.181001.epkg.Z | key_w_csum |
| 295a95d3de48b57da05e2a287845ec1fa30a5f6c1bc623bc112d8875d5e1f7f0 | IJ09622s4a.181001.epkg.Z | key_w_csum |
| 7f453dbc597c80ddcb87c019a2fb258ded6258a81709d3a4c5ee4eca56d2588a | IJ09622s5a.181001.epkg.Z | key_w_csum |
| b46a7800fd8ca18eaba43c31741987d4928ad99daf9eaefeb14340befd22c059 | IJ09622s6a.181001.epkg.Z | key_w_csum |
| fa7950e628b4d76a1c00865f4e5b4a8e514663a79f5cb2f7497b5d2099828f3f | IJ09623s2a.181002.epkg.Z | key_w_csum |
| ec15d06abdae9169cef5596dbe3e7a77216bd5e3af3066fc0562b4a5e9599a6c | IJ09623s3a.181002.epkg.Z | key_w_csum |
| 871348aff03053c4ba0f9b46ca0bbe768513bd64000820f42161fba485fc836c | IJ09623s4a.181002.epkg.Z | key_w_csum |
| 73062bc6662e52f6965c2ac4af6a2ac090046e808446920e1a33d477fe96a4c1 | IJ09624s0a.181002.epkg.Z | key_w_csum |
| e5ee7b489eea99c92765546c8be6a1ac13779d83107d9e70785862148d6fd7de | IJ09624s1a.181003.epkg.Z | key_w_csum |
| 33d0d44b86f3d00629ef232bc71490e1f2d6b8342c39e1d9ac034c9a0d16c5a0 | IJ09624s2a.181003.epkg.Z | key_w_csum |
| 2166aefe2baebce7d3982f7e091620f9cf97e66ad39711954313b9130e93e3fc | IJ09625s0a.181010.epkg.Z | key_w_csum |
| 714621b65a901d87f07565897763e907095812719a4f465b7a1170074b4c5f95 | IJ09625s2a.181203.epkg.Z | key_w_csum |

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
 
* <http://aix.software.ibm.com/aix/efixes/security/freebsd_advisory.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/freebsd_advisory.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/freebsd_advisory.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

An LPAR system reboot is required to complete the iFix installation,
or Live Update may be used on AIX 7.2 to avoid a reboot.

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

# WORKAROUNDS AND MITIGATIONS:

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
 
* Complete CVSS v3 Guide: <http://www.first.org/cvss/user-guide>
* On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

* IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>

* IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>

* Security Bulletin: Vulnerability in FreeBSD affects AIX (CVE-2018-6922) <https://www-01.ibm.com/support/docview.wss?uid=ibm10737709>

# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Thu Nov  8 14:04:12 CST 2018

Updated: Wed Dec  5 12:11:30 CST 2018

Update: iFixes now provided for AIX 7200-03-02 and VIOS 2.2.6.32, 3.1.0.0, and 3.1.0.10.


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



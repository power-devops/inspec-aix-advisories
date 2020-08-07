# IBM SECURITY ADVISORY

First Issued: Thu Feb  8 13:49:23 CST 2018 

Updated: Tue Feb 13 11:05:56 CST 2018

Update: CVE description was updated to provide additional detail.

The most recent version of this document is available here:

<http://aix.software.ibm.com/aix/efixes/security/aixbase_advisory.asc>

<https://aix.software.ibm.com/aix/efixes/security/aixbase_advisory.asc>

<ftp://aix.software.ibm.com/aix/efixes/security/aixbase_advisory.asc>

Security Bulletin: Vulnerability impacts AIX and VIOS (CVE-2018-1383) 

# SUMMARY:

IBM has released the following fixes for AIX and VIOS in response to CVE-2018-1383.

# VULNERABILITY DETAILS:

## CVEID: CVE-2018-1383
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1383
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1383
* **DESCRIPTION**
  A software logic bug creates a vulnerability in an AIX 6.1, 
  7.1, and 7.2 daemon which could allow a user with root privileges on 
  one system, to obtain root access on another machine.
* CVSS Base Score: 9.1
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/138117> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) 


# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX 6.1, 7.1, 7.2
* VIOS 2.2.x 

The vulnerabilities in the following filesets are being addressed:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.cluster.rte | 6.1.9.0 | 6.1.9.300 | key_w_fs |
| bos.cluster.rte | 7.1.4.0 | 7.1.4.32 | key_w_fs |
| bos.cluster.rte | 7.1.5.0 | 7.1.5.0 | key_w_fs |
| bos.cluster.rte | 7.2.0.0 | 7.2.0.5 | key_w_fs |
| bos.cluster.rte | 7.2.1.0 | 7.2.1.2 | key_w_fs |
| bos.cluster.rte | 7.2.2.0 | 7.2.2.0 | key_w_fs |
        
Note: to find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  ```lslpp -L | grep -i bos.cluster.rte```


# REMEDIATION:

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 6.1.9 | IJ02726 | ** | SP11 | key_w_apar |
| 7.1.4 | IJ02825 | ** | SP6 | key_w_apar |
| 7.1.5 | IJ02727 | ** | SP2 | key_w_apar |
| 7.2.0 | IJ02827 | ** | SP6 | key_w_apar |
| 7.2.1 | IJ02828 | ** | SP4 | key_w_apar |
| 7.2.2 | IJ02729 | ** | SP2 | key_w_apar |

Subscribe to the APARs here:

* http://www.ibm.com/support/docview.wss?uid=isg1IJ02726
* http://www.ibm.com/support/docview.wss?uid=isg1IJ02727
* http://www.ibm.com/support/docview.wss?uid=isg1IJ02729
* http://www.ibm.com/support/docview.wss?uid=isg1IJ02825
* http://www.ibm.com/support/docview.wss?uid=isg1IJ02827
* http://www.ibm.com/support/docview.wss?uid=isg1IJ02828
* https://www.ibm.com/support/docview.wss?uid=isg1IJ02726
* https://www.ibm.com/support/docview.wss?uid=isg1IJ02727
* https://www.ibm.com/support/docview.wss?uid=isg1IJ02729
* https://www.ibm.com/support/docview.wss?uid=isg1IJ02825
* https://www.ibm.com/support/docview.wss?uid=isg1IJ02827
* https://www.ibm.com/support/docview.wss?uid=isg1IJ02828

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX/VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/aixbase_fix.tar>
* <http://aix.software.ibm.com/aix/efixes/security/aixbase_fix.tar>
* <https://aix.software.ibm.com/aix/efixes/security/aixbase_fix.tar>

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.
            
| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 6.1.9.8 | IJ02726s8a.171221.epkg.Z | key_w_fix |
| 6.1.9.9 | IJ02726s9a.171221.epkg.Z | key_w_fix |
| 6.1.9.10 | IJ02726sAa.171221.epkg.Z | key_w_fix |
| 7.1.4.3 | IJ02825s3a.171221.epkg.Z | key_w_fix |
| 7.1.4.4 | IJ02825s4a.171221.epkg.Z | key_w_fix |
| 7.1.4.5 | IJ02825s5a.171221.epkg.Z | key_w_fix |
| 7.1.5.0 | IJ02727s1a.171221.epkg.Z | key_w_fix |
| 7.1.5.1 | IJ02727s1a.171221.epkg.Z | key_w_fix |
| 7.2.0.3 | IJ02827s3a.171221.epkg.Z | key_w_fix |
| 7.2.0.4 | IJ02827s4a.171221.epkg.Z | key_w_fix |
| 7.2.0.5 | IJ02827s5a.171221.epkg.Z | key_w_fix |
| 7.2.1.1 | IJ02828s1a.171221.epkg.Z | key_w_fix |
| 7.2.1.2 | IJ02828s2a.171221.epkg.Z | key_w_fix |
| 7.2.1.3 | IJ02828s3a.171221.epkg.Z | key_w_fix |
| 7.2.2.0 | IJ02729s1a.171221.epkg.Z | key_w_fix |
| 7.2.2.1 | IJ02729s1a.171221.epkg.Z | key_w_fix |
     
Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.1 is AIX 7200-02-01. 

| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.4.30 | IJ02726s8a.171221.epkg.Z | key_w_fix |
| 2.2.4.40 | IJ02726s9a.171221.epkg.Z | key_w_fix |
| 2.2.5.10 | IJ02726s8a.171221.epkg.Z | key_w_fix |
| 2.2.5.20 | IJ02726s9a.171221.epkg.Z | key_w_fix  |
| 2.2.5.30 | IJ02726sAa.171221.epkg.Z | key_w_fix |
| 2.2.6.0 | IJ02726sAa.171221.epkg.Z | key_w_fix |
| 2.2.6.10 | IJ02726sAa.171221.epkg.Z | key_w_fix |
            
To extract the fixes from the tar file:

```
tar xvf aixbase_fix.tar
cd aixbase_fix
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the ```openssl dgst -sha256 file``` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 77a66084b51a448510fb01af2633b3b43589ae64df4e1a1407a0030e8699ddc0 | IJ02726s8a.171221.epkg.Z | key_w_csum |
| 1e854be8068ad5b9ee4ddd30570144d9b14dcf37d2db574f9b4268345ac3a28b | IJ02726s9a.171221.epkg.Z | key_w_csum |
| c6dd5ccdb979a9a17e7a4266e5c6e0af4b25281921f165276ad159401ff5aa86 | IJ02726sAa.171221.epkg.Z | key_w_csum |
| d3422b3a86b68fc986078633ac00791115773e6a520ec939aa7d55dfe451ead4 | IJ02727s1a.171221.epkg.Z | key_w_csum |
| 90cb1c39ac03158c924fc0785ca62f456d2cb454736507b1df0b6a71b83912e8 | IJ02729s1a.171221.epkg.Z | key_w_csum |
| 663804ccb7ccb319a0da68ff157cc41de20e1df23c7cfa4375dcf036cfbf26b8 | IJ02825s3a.171221.epkg.Z | key_w_csum |
| 040157614b623e8de55a066b8e1db82fa87af6cbfd4f9d1dbac0236c7aadc934 | IJ02825s4a.171221.epkg.Z | key_w_csum |
| f33ef3d8441b0b1726df92be7027ba274c7e95eaa088bddc2f91ef3edef551a4 | IJ02825s5a.171221.epkg.Z | key_w_csum |
| 6beca72bde8ad0da0634ca17e39e614e21e127e5960dd3ffef10af84a8c84685 | IJ02827s3a.171221.epkg.Z | key_w_csum |
| dc47a6f5ec8f5530d77b288dd972f64945281b8637d207a7884fb1c7cea02093 | IJ02827s4a.171221.epkg.Z | key_w_csum |
| 475cded7dbaf56e39937fe1418b9a09a6ebb3c66e161d49890f129f5c89830c9 | IJ02827s5a.171221.epkg.Z | key_w_csum |
| 7beb4d34d7d0a7e46a899a66f610a5959b6eff35872a87aa1cf7d7d24bef9294 | IJ02828s1a.171221.epkg.Z | key_w_csum |
| 07359a15361720147a7897acbe4757f6a0bb0ef1d027817f478146e6366e76bb | IJ02828s2a.171221.epkg.Z | key_w_csum |
| 2683bfdc36327dd8cfbd49ad3f4521d3711cc3af49138314b8f7e4665b8ed4b7 | IJ02828s3a.171221.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at <http://ibm.com/support/> and describe the discrepancy.         
 
```
openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
``` 
 
```
openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/aixbase_advisory.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/aixbase_advisory.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/aixbase_advisory.asc.sig>

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

<http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html>

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

# CONTACT US:

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

To obtain the OpenSSL public key that can be used to verify the signed advisories and ifixes:

Download the key from our web page:

<http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.

# REFERENCES:
 
* Complete CVSS v3 Guide:  <http://www.first.org/cvss/user-guide>
* On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>

# RELATED INFORMATION:

* IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>
* IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>
* Security Bulletin: Vulnerability impacts AIX and VIOS (CVE-2018-1383) <http://www-01.ibm.com/support/docview.wss?uid=isg3T1026948>


# ACKNOWLEDGEMENTS:

None.

# CHANGE HISTORY:

First Issued: Thu Feb  8 13:49:23 CST 2018 

Updated: Tue Feb 13 11:05:56 CST 2018

Update: CVE description was updated to provide additional detail.


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


# IBM SECURITY ADVISORY

First Issued: Tue Dec 11 09:25:56 CST 2018

The most recent version of this document is available here:
* <http://aix.software.ibm.com/aix/efixes/security/solaris_advisory.asc>
* <https://aix.software.ibm.com/aix/efixes/security/solaris_advisory.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/solaris_advisory.asc>

Security Bulletin: Vulnerability in Oracle Solaris affects AIX (CVE-2017-3623)

# SUMMARY

There is a vulnerability in Oracle Solaris that affects AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2017-3623
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3623>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3623>
* **DESCRIPTION**
  An unspecified vulnerability in Oracle Sun Systems related 
  to the Solaris Kernel RPC component could allow an unauthenticated 
  attacker to take control of the system.
* CVSS Base Score: 10
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/124996 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)


# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX 5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x 

The following fileset levels are vulnerable:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.client | 5.3.12.0 | 5.3.12.10 | key_w_fs |
| bos.net.tcp.client | 6.1.9.0 | 6.1.9.400 | key_w_fs |
| bos.net.tcp.client | 7.1.4.0 | 7.1.4.33 | key_w_fs |
| bos.net.tcp.client | 7.1.5.0 | 7.1.5.30 | key_w_fs |
| bos.net.tcp.client_core | 7.2.0.0 | 7.2.0.5 | key_w_fs |
| bos.net.tcp.client_core | 7.2.1.0 | 7.2.1.3 | key_w_fs |
| bos.net.tcp.client_core | 7.2.2.0 | 7.2.2.16 | key_w_fs |
| bos.net.tcp.client_core | 7.2.3.0 | 7.2.3.0 | key_w_fs |
        
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

	lslpp -L | grep -i bos.net.tcp.client


# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 5.3.12 | IJ10554 | ** | N/A | key_w_apar |
| 6.1.9 | IJ10134 | ** | SP12-1846 | key_w_apar |
| 7.1.4 | IJ10275 | ** | SP07-1845 | key_w_apar |
| 7.1.5 | IJ10132 | ** | SP03-1846 | key_w_apar |
| 7.2.0 | IJ10553 | ** | N/A | key_w_apar |
| 7.2.1 | IJ10552 | ** | SP05-1845 | key_w_apar |
| 7.2.2 | IJ10130 | ** | SP03-1845 | key_w_apar |
| 7.2.3 | IJ09805 | ** | SP02-1845 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.4 | IJ10134 | ** | N/A | key_w_apar |
| 2.2.5 | IJ10134 | ** | 2.2.5.50 | key_w_apar |
| 2.2.6 | IJ10134 | ** | 2.2.6.32 | key_w_apar |

Subscribe to the APARs here:

* http://www.ibm.com/support/docview.wss?uid=isg1IJ10554
* http://www.ibm.com/support/docview.wss?uid=isg1IJ10134
* http://www.ibm.com/support/docview.wss?uid=isg1IJ10275
* http://www.ibm.com/support/docview.wss?uid=isg1IJ10132
* http://www.ibm.com/support/docview.wss?uid=isg1IJ10553
* http://www.ibm.com/support/docview.wss?uid=isg1IJ10552
* http://www.ibm.com/support/docview.wss?uid=isg1IJ10130
* http://www.ibm.com/support/docview.wss?uid=isg1IJ09805

* https://www.ibm.com/support/docview.wss?uid=isg1IJ10554
* https://www.ibm.com/support/docview.wss?uid=isg1IJ10134
* https://www.ibm.com/support/docview.wss?uid=isg1IJ10275
* https://www.ibm.com/support/docview.wss?uid=isg1IJ10132
* https://www.ibm.com/support/docview.wss?uid=isg1IJ10553
* https://www.ibm.com/support/docview.wss?uid=isg1IJ10552
* https://www.ibm.com/support/docview.wss?uid=isg1IJ10130
* https://www.ibm.com/support/docview.wss?uid=isg1IJ09805

By subscribing, you will receive periodic email alerting you to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

After iFix installation, an LPAR system reboot is recommended.
In lieu of a reboot, processes using RPC services may be stopped
and restarted. Please refer to the rpcinfo command to view running
RPC services. Programs/daemons running those RPC services must be
restarted.

The AIX and VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/solaris_fix.tar>
* <http://aix.software.ibm.com/aix/efixes/security/solaris_fix.tar>
* <https://aix.software.ibm.com/aix/efixes/security/solaris_fix.tar> 

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

| AIX Level | Interim Fix (*.Z) | KEY |
| --------- | ----------------- | --- |
| 5.3.12.9 | IJ10554s9a.181017.epkg.Z | key_w_fix |
| 6.1.9.10 | IJ10134sAa.181009.epkg.Z | key_w_fix |
| 6.1.9.11 | IJ10134sBa.181009.epkg.Z | key_w_fix |
| 6.1.9.11 | IJ10134sBb.181009.epkg.Z | key_w_fix |
| 6.1.9.12 | IJ10134sCa.181009.epkg.Z | key_w_fix |
| 7.1.4.4 | IJ10275s4a.181009.epkg.Z | key_w_fix |
| 7.1.4.5 | IJ10275s5a.181009.epkg.Z | key_w_fix |
| 7.1.4.6 | IJ10275s6a.181009.epkg.Z | key_w_fix |
| 7.1.5.1 | IJ10132s1a.181009.epkg.Z | key_w_fix |
| 7.1.5.2 | IJ10132s2a.181009.epkg.Z | key_w_fix |
| 7.1.5.2 | IJ10132s2b.181009.epkg.Z | key_w_fix |
| 7.1.5.3 | IJ10132s3a.181009.epkg.Z | key_w_fix |
| 7.2.0.4 | IJ10553s4a.181016.epkg.Z | key_w_fix |
| 7.2.0.5 | IJ10553s5a.181016.epkg.Z | key_w_fix |
| 7.2.0.6 | IJ10553s6a.181016.epkg.Z | key_w_fix |
| 7.2.1.2 | IJ10552s2a.181016.epkg.Z | key_w_fix |
| 7.2.1.3 | IJ10552s3a.181016.epkg.Z | key_w_fix |
| 7.2.1.4 | IJ10552s4a.181016.epkg.Z | key_w_fix |
| 7.2.2.0 | IJ10130s0a.181011.epkg.Z | key_w_fix |
| 7.2.2.1 | IJ10130s0a.181011.epkg.Z | key_w_fix |
| 7.2.2.2 | IJ10130s2a.181011.epkg.Z | key_w_fix |
| 7.2.2.2 | IJ10130s2b.181011.epkg.Z | key_w_fix |
| 7.2.3.0 | IJ09805s0a.181012.epkg.Z | key_w_fix |
| 7.2.3.1 | IJ09805s0a.181012.epkg.Z | key_w_fix |
    
Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.1 is AIX 7200-02-01.

NOTE: Multiple iFixes are provided for AIX 6100-09-11, 7100-05-02, and 7200-02-02.
* IJ10134sBa is for AIX 6100-09-11 with bos.net.tcp.client fileset level 6.1.9.315.
* IJ10134sBb is for AIX 6100-09-11 with bos.net.tcp.client fileset level 6.1.9.316.
* IJ10132s2a is for AIX 7100-05-02 with bos.net.tcp.client fileset level 7.1.5.15.
* IJ10132s2b is for AIX 7100-05-02 with bos.net.tcp.client fileset level 7.1.5.16.
* IJ10130s2a is for AIX 7200-02-02 with bos.net.tcp.client_core fileset level 7.2.2.15.
* IJ10130s2b is for AIX 7200-02-02 with bos.net.tcp.client_core fileset level 7.2.2.16.
 
Please reference the Affected Products and Version section above
for help with checking installed fileset levels.

| VIOS Level | Interim Fix (*.Z) | KEY |
| ---------- | ----------------- | --- |
| 2.2.4.60 | IJ10134sBa.181009.epkg.Z | key_w_fix |
| 2.2.5.40 | IJ10134sBa.181009.epkg.Z | key_w_fix |
| 2.2.6.20 | IJ10134sBa.181009.epkg.Z | key_w_fix |
| 2.2.6.21 | IJ10134sBa.181009.epkg.Z | key_w_fix |
| 2.2.6.23 | IJ10134sBb.181009.epkg.Z | key_w_fix |
| 2.2.6.30 | IJ10134sCa.181009.epkg.Z | key_w_fix |
| 2.2.6.31 | IJ10134sCa.181009.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
            tar xvf solaris_fix.tar
            cd solaris_fix
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the `openssl dgst -sha256 [filename]` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| 3361de83cc5cd752a4633f6363ef67c80d179740e65fb7e4ed69581daba2ba8e | IJ09805s0a.181012.epkg.Z | key_w_csum |
| 561c4f14440c4bbc67cd9ddf71d16c04f75b2bdb8de5ef7a365f7c67ac180dba | IJ10130s0a.181011.epkg.Z | key_w_csum |
| 3a8b2e9a4060212a3cf2d4b5d462605e2ac073a6434b623c19c7634b61a51e06 | IJ10130s2a.181011.epkg.Z | key_w_csum |
| befbe84cd8bcdfd8a4c56a6e543721be85ea9bd66893f13996b4cefc75fa6f8e | IJ10130s2b.181011.epkg.Z | key_w_csum |
| 47991453c69e353822dfc10035c3370d422853d491aeeb1062dc5c9e196a077f | IJ10132s1a.181009.epkg.Z | key_w_csum |
| 354c03e24a648acfe7fb8516fa043b1fcfe1b2739188eb85b3973673e50a0d39 | IJ10132s2a.181009.epkg.Z | key_w_csum |
| a72972107ceb3e6fa1408d7c3e3277b2926d9f6c62cb2100de2b8fe6678aa738 | IJ10132s2b.181009.epkg.Z | key_w_csum |
| 8517c019727df9fb65ad59d0f51bdc9c550e4f3c1b2cd0f9ffe9f8eee46a514a | IJ10132s3a.181009.epkg.Z | key_w_csum |
| dea142ac623e9a54fe36ba4d5ffe1e3a472c1071603864c2b8a15a938e2f8e8f | IJ10134sAa.181009.epkg.Z | key_w_csum |
| a7bc11276427338eaa3eb399c7c8b44189911f7dff17f86e82c754cb79574934 | IJ10134sBa.181009.epkg.Z | key_w_csum |
| f3a0758fdf91d710dac3c8ebc899ec41d2321ac5ffba8bbf3f8671c9874771da | IJ10134sBb.181009.epkg.Z | key_w_csum |
| 168868a77bddb52b210b1c8b0122cbad0f42b31a3917f79b5f9eb227825cf004 | IJ10134sCa.181009.epkg.Z | key_w_csum |
| 7ccc5910e339cc5266419dbba50342b25577a9bb97982cc6d04e841226b37bad | IJ10275s4a.181009.epkg.Z | key_w_csum |
| f11f3f359f6b685463fbbbc83ae698157ab76b825567f125bb007e079bd83867 | IJ10275s5a.181009.epkg.Z | key_w_csum |
| 7f27c0f0f6cc3d6674a5618d690dbb30013da5e172305a9d01440437abaf74c7 | IJ10275s6a.181009.epkg.Z | key_w_csum |
| 7ff683e5284d686ea8f52fb5d895ba0b3303de6a33552e5855d2ea8a284ef6fa | IJ10552s2a.181016.epkg.Z | key_w_csum |
| 9747cef73298ba097e9256fb00cc3babac83f4d2628888798a0cfa140cc354fa | IJ10552s3a.181016.epkg.Z | key_w_csum |
| 8fa9f4c5ab555ab3a348a8effa1938b53857a1c334e53ab359f43e8fff85429b | IJ10552s4a.181016.epkg.Z | key_w_csum |
| ba67396c66996de2a52610bdf7bb44ad28cd4eb97345c62d6e11787e56cbab7e | IJ10553s4a.181016.epkg.Z | key_w_csum |
| e9b817c683b27e09233086fff50f6d7bec635d9617975dfb20b5d4ee65feed58 | IJ10553s5a.181016.epkg.Z | key_w_csum |
| 6bb35b3a311479b8f72813d90ca441b11af929268e42aec9d52906f618d2b76d | IJ10553s6a.181016.epkg.Z | key_w_csum |
| 40d3f722f63b2f315f81f530b48869714a86a7c25653d339c7fc6aba59235e5e | IJ10554s9a.181017.epkg.Z | key_w_csum |

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
 
* <http://aix.software.ibm.com/aix/efixes/security/solaris_advisory.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/solaris_advisory.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/solaris_advisory.asc.sig>

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

# WORKAROUNDS AND MITIGATIONS

A fix is not required if RPC services are not running. You
can check for running RPC services with the "rpcinfo -p" command.

If there are RPC services running that are not required to run,
you can do the following to stop RPC services:

1. Comment out the rc.nfs line in /etc/inittab (To comment in 
this file, use colon space at the beginning of the line,  ": ")

```
$ vim /etc/inittab  
...
: rcnfs:23456789:wait:/etc/rc.nfs > /dev/console 2>&1 # Start NFS Daemons
...
```

2. Comment out the lines that start portmap in /etc/rc.tcpip

```
$ vim /etc/rc.tcpip
...
# portmap_pid=`ps -e | awk '$NF == "portmap" {print $1}'`
# [ -z "$portmap_pid" ] && start /usr/sbin/portmap "${src_running}"
...
```

3. Reboot 


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing purposes.

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
 
Complete CVSS v3 Guide: <http://www.first.org/cvss/user-guide>

On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>

IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>

Security Bulletin: Vulnerability in Oracle Solaris affects AIX (CVE-2017-3623)
<https://www-01.ibm.com/support/docview.wss?uid=ibm10742315>


# ACKNOWLEDGEMENTS

The vulnerability was reported to IBM by Harrison Neal (hantwister).


# CHANGE HISTORY

First Issued: Tue Dec 11 09:25:56 CST 2018


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




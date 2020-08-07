# IBM SECURITY ADVISORY

First Issued: Mon Feb  5 13:19:26 CST 2018

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/suid_advisory.asc>
* <https://aix.software.ibm.com/aix/efixes/security/suid_advisory.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/suid_advisory.asc>


Security Bulletin: Vulnerabilities in bellmail, caccelstat, iostat, lquerypv,
restbyinode, and vmstat affect AIX (CVE-2017-1692) 
 
# SUMMARY

There is a potential root privilege escalation vulnerability in bellmail,
caccelstat, iostat, lquerypv, restbyinode, and vmstat on AIX. 


# VULNERABILITY DETAILS:

## CVEID: CVE-2017-1692
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1692>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1692>
* **DESCRIPTION**
  IBM AIX contains an unspecified vulnerability that would
  allow a locally authenticated user to obtain root level privileges. 
* CVSS Base Score: 8.4
* CVSS Temporal Score: See https://exchange.xforce.ibmcloud.com/vulnerabilities/134067 for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

# AFFECTED PRODUCTS AND VERSIONS:
 
* AIX  5.3, 6.1, 7.1, 7.2
* VIOS 2.2.x
        
The following fileset levels are vulnerable:
        
key_fileset = aix

## For bellmail:

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.client | 6.1.9.0 | 6.1.9.201 | key_w_fs |
| bos.net.tcp.client | 7.1.4.0 | 7.1.4.32 | key_w_fs |
| bos.net.tcp.client_core | 7.2.0.0 | 7.2.0.4 | key_w_fs |
| bos.net.tcp.client_core | 7.2.1.0 | 7.2.1.2 | key_w_fs |


## For caccelstat:

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.acct | 7.2.0.0 | 7.2.0.2 | key_w_fs |
| bos.acct | 7.2.1.0 | 7.2.1.0 | key_w_fs |


## For iostat:

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.acct | 7.1.4.0 | 7.1.4.30 | key_w_fs |
| bos.acct | 7.2.0.0 | 7.2.0.3 | key_w_fs |
| bos.acct | 7.2.1.0 | 7.2.1.1 | key_w_fs |


## For lquerypv:

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.rte.lvm | 5.3.12.0 | 5.3.12.8 | key_w_fs | 
| bos.rte.lvm | 6.1.9.0 | 6.1.9.201 | key_w_fs | 
| bos.rte.lvm | 7.1.4.0 | 7.1.4.32 | key_w_fs | 
| bos.rte.lvm | 7.2.0.0 | 7.2.0.4 | key_w_fs | 
| bos.rte.lvm | 7.2.1.0 | 7.2.1.2 | key_w_fs | 


## For restbyinode:

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.rte.archive | 5.3.12.0 | 5.3.12.7 | key_w_fs | 
| bos.rte.archive | 6.1.9.0 | 6.1.9.201 | key_w_fs | 
| bos.rte.archive | 7.1.4.0 | 7.1.4.31 | key_w_fs | 
| bos.rte.archive | 7.2.0.0 | 7.2.0.3 | key_w_fs | 
| bos.rte.archive | 7.2.1.0 | 7.2.1.1 | key_w_fs | 


## For vmstat:

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.acct | 7.1.4.0 | 7.1.4.30 | key_w_fs |
| bos.acct | 7.2.0.0 | 7.2.0.3 | key_w_fs |
| bos.acct | 7.2.1.0 | 7.2.1.1 | key_w_fs |
 
Note:  To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in the AIX user's
guide.

Example:  ```lslpp -L | grep -i bos.net.tcp.client```

# REMEDIATION:

## A. APARS
            
IBM has assigned the following APARs to this problem:

### For bellmail:

| AIX Level | APAR | SP | KEY |
| --------- | ---- | -- | --- |
| 6.1.9 | IV97356 | SP10 | key_w_apar |
| 7.1.4 | IV99497 | SP6 | key_w_apar |
| 7.2.0 | IV99498 | SP6 | key_w_apar |
| 7.2.1 | IV99499 | SP4 | key_w_apar |


### For caccelstat:

| AIX Level | APAR | SP | KEY |
| --------- | ---- | -- | --- |
| 7.2.0 | IV97810 | SP5 | key_w_apar |
| 7.2.1 | IV97811 | SP3 | key_w_apar |


### For iostat:

| AIX Level | APAR | SP | KEY |
| --------- | ---- | -- | --- |
| 7.1.4 | IV97896 | SP6 | key_w_apar |
| 7.2.0 | IV97897 | SP6 | key_w_apar |
| 7.2.1 | IV97898 | SP4 | key_w_apar |


### For lquerypv:

| AIX Level | APAR | SP | KEY |
| --------- | ---- | -- | --- |
| 5.3.12 | IJ00951 | N/A | key_w_apar |
| 6.1.9 | IV99548 | SP10 | key_w_apar |
| 7.1.4 | IV99550 | SP6 | key_w_apar |
| 7.2.0 | IV99551 | SP6 | key_w_apar |
| 7.2.1 | IV99552 | SP4 | key_w_apar |


### For restbyinode:

| AIX Level | APAR | SP | KEY |
| --------- | ---- | -- | --- |
| 5.3.12 | IV98013 | N/A | key_w_apar |
| 6.1.9 | IV97852 | SP10 | key_w_apar |
| 7.1.4 | IV97957 | SP6 | key_w_apar |
| 7.2.0 | IV97959 | SP6 | key_w_apar |
| 7.2.1 | IV97958 | SP4 | key_w_apar |


### For vmstat:

| AIX Level | APAR | SP | KEY |
| --------- | ---- | -- | --- |
| 7.1.4 | IV97899 | SP6 | key_w_apar |
| 7.2.0 | IV97900 | SP6 | key_w_apar |
| 7.2.1 | IV97901 | SP4 | key_w_apar |
 
* Please refer to AIX support lifecycle information page for 
 availability of Service Packs: <http://www-01.ibm.com/support/docview.wss?uid=isg3T1012517>

Subscribe to the APARs here:

### For bellmail:
* http://www.ibm.com/support/docview.wss?uid=isg1IV97356
* https://www.ibm.com/support/docview.wss?uid=isg1IV97356
* http://www.ibm.com/support/docview.wss?uid=isg1IV99497
* https://www.ibm.com/support/docview.wss?uid=isg1IV99497
* http://www.ibm.com/support/docview.wss?uid=isg1IV99498
* https://www.ibm.com/support/docview.wss?uid=isg1IV99498
* http://www.ibm.com/support/docview.wss?uid=isg1IV99499
* https://www.ibm.com/support/docview.wss?uid=isg1IV99499

### For caccelstat:
* http://www.ibm.com/support/docview.wss?uid=isg1IV97810
* https://www.ibm.com/support/docview.wss?uid=isg1IV97810
* http://www.ibm.com/support/docview.wss?uid=isg1IV97811
* https://www.ibm.com/support/docview.wss?uid=isg1IV97811

### For iostat:
* http://www.ibm.com/support/docview.wss?uid=isg1IV97896
* https://www.ibm.com/support/docview.wss?uid=isg1IV97896
* http://www.ibm.com/support/docview.wss?uid=isg1IV97898
* https://www.ibm.com/support/docview.wss?uid=isg1IV97898

### For lquerypv:
* http://www.ibm.com/support/docview.wss?uid=isg1IJ00951
* https://www.ibm.com/support/docview.wss?uid=isg1IJ00951
* http://www.ibm.com/support/docview.wss?uid=isg1IV99548
* https://www.ibm.com/support/docview.wss?uid=isg1IV99548
* http://www.ibm.com/support/docview.wss?uid=isg1IV99550
* https://www.ibm.com/support/docview.wss?uid=isg1IV99550
* http://www.ibm.com/support/docview.wss?uid=isg1IV99551
* https://www.ibm.com/support/docview.wss?uid=isg1IV99551 
* http://www.ibm.com/support/docview.wss?uid=isg1IV99552
* https://www.ibm.com/support/docview.wss?uid=isg1IV99552

### For restbyinode:
* http://www.ibm.com/support/docview.wss?uid=isg1IV97852
* https://www.ibm.com/support/docview.wss?uid=isg1IV97852
* http://www.ibm.com/support/docview.wss?uid=isg1IV97957
* https://www.ibm.com/support/docview.wss?uid=isg1IV97957
* http://www.ibm.com/support/docview.wss?uid=isg1IV97958
* https://www.ibm.com/support/docview.wss?uid=isg1IV97958
* http://www.ibm.com/support/docview.wss?uid=isg1IV97959
* https://www.ibm.com/support/docview.wss?uid=isg1IV97959
* http://www.ibm.com/support/docview.wss?uid=isg1IV98013
* https://www.ibm.com/support/docview.wss?uid=isg1IV98013

### For vmstat:
* http://www.ibm.com/support/docview.wss?uid=isg1IV97899
* https://www.ibm.com/support/docview.wss?uid=isg1IV97899
* http://www.ibm.com/support/docview.wss?uid=isg1IV97900
* https://www.ibm.com/support/docview.wss?uid=isg1IV97900
* http://www.ibm.com/support/docview.wss?uid=isg1IV97901
* https://www.ibm.com/support/docview.wss?uid=isg1IV97901

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

Fixes are available.

The fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/suid_fix.tar>
* <http://aix.software.ibm.com/aix/efixes/security/suid_fix.tar>
* <https://aix.software.ibm.com/aix/efixes/security/suid_fix.tar>

The links above are to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

Please note that the below tables refer to AIX TL/SP level as
opposed to fileset level, i.e., 6.1.9.9 is AIX 6100-09-09.


### For bellmail:

| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 6.1.9.7 | IV97356m9a.170830.epkg.Z | key_w_fix | bellmail |
| 6.1.9.8 | IV97356m9a.170830.epkg.Z | key_w_fix | bellmail |
| 6.1.9.9 | IV97356m9a.170830.epkg.Z | key_w_fix | bellmail |
| 7.1.4.3 | IV99497m5a.171115.epkg.Z | key_w_fix | bellmail |
| 7.1.4.4 | IV99497m5a.171115.epkg.Z | key_w_fix | bellmail |
| 7.1.4.5 | IV99497m5a.171115.epkg.Z | key_w_fix | bellmail |
| 7.2.0.3 | IV99498m5a.171115.epkg.Z | key_w_fix | bellmail |
| 7.2.0.4 | IV99498m5a.171115.epkg.Z | key_w_fix | bellmail |
| 7.2.0.5 | IV99498m5a.171115.epkg.Z | key_w_fix | bellmail |
| 7.2.1.1 | IV99499m3a.171115.epkg.Z | key_w_fix | bellmail |
| 7.2.1.2 | IV99499m3a.171115.epkg.Z | key_w_fix | bellmail |
| 7.2.1.3 | IV99499m3a.171115.epkg.Z | key_w_fix | bellmail |

| VIOS Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| ---------- | ----------------- | --- | ---------- |
| 2.2.4.x | IV97356m9a.170830.epkg.Z | key_w_fix | bellmail |
| 2.2.5.x | IV97356m9a.170830.epkg.Z | key_w_fix | bellmail |


### For caccelstat:

| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 7.2.0.3 | IV97811s2a.170712.epkg.Z | key_w_fix | caccelstat |
| 7.2.0.4 | IV97811s2a.170712.epkg.Z | key_w_fix | caccelstat |
| 7.2.0.5 | IV97811s2a.170712.epkg.Z | key_w_fix | caccelstat |
| 7.2.1.1 | IV97811s2a.170712.epkg.Z | key_w_fix | caccelstat |
| 7.2.1.2 | IV97811s2a.170712.epkg.Z | key_w_fix | caccelstat |
| 7.2.1.3 | IV97811s2a.170712.epkg.Z | key_w_fix | caccelstat |


### For iostat:

| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 7.1.4.3 | IV97896s4a.170712.epkg.Z | key_w_fix | iostat |
| 7.1.4.4 | IV97896s4a.170712.epkg.Z | key_w_fix | iostat |
| 7.1.4.5 | IV97896s4a.170712.epkg.Z | key_w_fix | iostat |
| 7.2.0.3 | IV97898s2a.171201.epkg.Z | key_w_fix | iostat |
| 7.2.0.4 | IV97898s2a.171201.epkg.Z | key_w_fix | iostat |
| 7.2.0.5 | IV97898s2a.171201.epkg.Z | key_w_fix | iostat |
| 7.2.1.1 | IV97898s2a.171201.epkg.Z | key_w_fix | iostat |
| 7.2.1.2 | IV97898s2a.171201.epkg.Z | key_w_fix | iostat |
| 7.2.1.3 | IV97898s2a.171201.epkg.Z | key_w_fix | iostat |


### For lquerypv:
           
| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 5.3.12.9 | IJ00951s9a.171031.epkg.Z | key_w_fix | lquerypv |
| 6.1.9.7 | IV99548m9a.171031.epkg.Z | key_w_fix | lquerypv |
| 6.1.9.8 | IV99548m9a.171031.epkg.Z | key_w_fix | lquerypv |
| 6.1.9.9 | IV99548m9a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.1.4.3 | IV99550m5a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.1.4.4 | IV99550m5a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.1.4.5 | IV99550m5a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.2.0.3 | IV99551m5a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.2.0.4 | IV99551m5a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.2.0.5 | IV99551m5a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.2.1.1 | IV99552m3a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.2.1.2 | IV99552m3a.171031.epkg.Z | key_w_fix | lquerypv |
| 7.2.1.3 | IV99552m3a.171031.epkg.Z | key_w_fix | lquerypv |

| VIOS Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| ---------- | ----------------- | --- | ---------- |
| 2.2.4.x | IV99548m9a.171031.epkg.Z | key_w_fix | lquerypv |
| 2.2.5.x | IV99548m9a.171031.epkg.Z | key_w_fix | lquerypv |


### For restbyinode:

| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 5.3.12.9 | IV98013s9a.170717.epkg.Z | key_w_fix | restbyinode |
| 6.1.9.7 | IV97852s7a.170713.epkg.Z | key_w_fix | restbyinode |
| 6.1.9.8 | IV97852s7a.170713.epkg.Z | key_w_fix | restbyinode |
| 6.1.9.9 | IV97852s7a.170713.epkg.Z | key_w_fix | restbyinode |
| 7.1.4.3 | IV97957s2b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.1.4.4 | IV97957s2b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.1.4.5 | IV97957s2b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.2.0.3 | IV97959s2b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.2.0.4 | IV97959s2b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.2.0.5 | IV97959s2b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.2.1.1 | IV97958s0b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.2.1.2 | IV97958s0b.171205.epkg.Z | key_w_fix | restbyinode |
| 7.2.1.3 | IV97958s0b.171205.epkg.Z | key_w_fix | restbyinode |

| VIOS Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| ---------- | ----------------- | --- | ---------- |
| 2.2.4.x | IV97852s7a.170713.epkg.Z | key_w_fix | restbyinode |
| 2.2.5.x | IV97852s7a.170713.epkg.Z | key_w_fix | restbyinode |


### For vmstat:

| AIX Level | Interim Fix (*.Z) | KEY | PRODUCT(S) |
| --------- | ----------------- | --- | ---------- |
| 7.1.4.3 | IV97899s4a.170712.epkg.Z | key_w_fix | vmstat |
| 7.1.4.4 | IV97899s4a.170712.epkg.Z | key_w_fix | vmstat |
| 7.1.4.5 | IV97899s4a.170712.epkg.Z | key_w_fix | vmstat |
| 7.2.0.3 | IV97901s2a.171201.epkg.Z | key_w_fix | vmstat |
| 7.2.0.4 | IV97901s2a.171201.epkg.Z | key_w_fix | vmstat |
| 7.2.0.5 | IV97901s2a.171201.epkg.Z | key_w_fix | vmstat |
| 7.2.1.1 | IV97901s2a.171201.epkg.Z | key_w_fix | vmstat |
| 7.2.1.2 | IV97901s2a.171201.epkg.Z | key_w_fix | vmstat |
| 7.2.1.3 | IV97901s2a.171201.epkg.Z | key_w_fix | vmstat |

                       
The above fixes are cumulative and address previously issued
AIX security bulletins with respect to binary, SP, and TL.           

To extract the fixes from the tar file:

```
            tar xvf suid_fix.tar
            cd suid_fix
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the ```openssl dgst -sha256 [filename]``` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| a91f0cd6b294227ceb043fe99b6fb5c8b408d990d03a2b3a08c1754050b3f7a7 | IJ00951s9a.171031.epkg.Z | key_w_csum |
| a1a3696b78746d0fa1c8a9a38d5439c1ff79ba9b1a5e638124e4a25949a71429 | IV97356m9a.170830.epkg.Z | key_w_csum |
| c082f6ffe8f0f6fc5acf0df1f74eb2205a214ae23dabfee0e4cd759e707a5706 | IV97811s2a.170712.epkg.Z | key_w_csum |
| 0ea5265c52e138023ba046fd22c3fcb608e3f3de30dc73bb6bf9e2c84e472544 | IV97852s7a.170713.epkg.Z | key_w_csum |
| e6d69a6719bfe59ed346e0c65155e84afe5a1640027fb79fa48d3d644ce54aaf | IV97896s4a.170712.epkg.Z | key_w_csum |
| c43608f1b64b0220456aff0cda22b8d72a95e571e42364154ef189911218353e | IV97898s2a.171201.epkg.Z | key_w_csum |
| 784fc0d14370e5725f0c5294636f6f26882bf017875b8c764034db06eb8b5a4e | IV97899s4a.170712.epkg.Z | key_w_csum |
| d7c8e44dfd74dd73cf1f20eca72a638392e2e5ab232e5475eb09c9237a7b540c | IV97901s2a.171201.epkg.Z | key_w_csum |
| f19d6b09dcc7849fb76198db05a87fb31dd01a7d4052017a19e32d0fdf0d2352 | IV97957s2b.171205.epkg.Z | key_w_csum |
| 0bcde1509bc593962f44b42d25a4bc888901d6334aa1605e7f7ff4a80b6e3a85 | IV97958s0b.171205.epkg.Z | key_w_csum |
| 8af449ba05c85d024e0a34905da3f5363c7a18f987d6cc45f99c37252ecfb180 | IV97959s2b.171205.epkg.Z | key_w_csum |
| 8e381f9e9703c246bfb5ef2b64231485aaa2ad8c81a90d7e724665e46cc633f8 | IV98013s9a.170717.epkg.Z | key_w_csum |
| 7027d0d8ac6001323058462322c71b873681482d3ccaf3f4c3c14d579f80eb90 | IV99497m5a.171115.epkg.Z | key_w_csum |
| bacab656bb61f01a9f242f0620b769f65bdc79a047a53523d384fdbe7ffd63ed | IV99498m5a.171115.epkg.Z | key_w_csum |
| 1db7238f02d940bdb9bd8cd2710e54287b593d2e6283588f53bcd9b526d8999a | IV99499m3a.171115.epkg.Z | key_w_csum |
| 7ad19e632a57c699cefc02c20940fb3e990a04717108d3a400a97424bee78b9a | IV99548m9a.171031.epkg.Z | key_w_csum |
| 14064b0be5b940a349d4c4837e5791f64061dab35ffd0e3eb60cb5a6f30a358c | IV99550m5a.171031.epkg.Z | key_w_csum |
| 37359dbd4c06b36a7ae3d555e5f3d121e04825ec385af31b6006451abe9e82da | IV99551m5a.171031.epkg.Z | key_w_csum |
| 25bef666dea79510eb090451833937dafdeebc343bb00044284bfa3f0d532a95 | IV99552m3a.171031.epkg.Z | key_w_csum |

These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at <http://ibm.com/support/> and describe the discrepancy.
           
```
            openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
 
            openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
``` 

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/suid_advisory.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/suid_advisory.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/suid_advisory.asc.sig>

## C. FIX AND INTERIM FIX INSTALLATION

**IMPORTANT** : If possible, it is recommended that a mksysb backup
of the system be created.  Verify it is both bootable and
readable before proceeding.

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
* <https://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html>

To preview an interim fix installation:

```
            emgr -e epkg_name -p         # where epkg_name is the name of the
                                         # interim fix package being previewed.
```

To install an interim fix package:

```
            emgr -e epkg_name -X         # where epkg_name is the name of the
                                         # interim fix package being installed.
```


# WORKAROUNDS AND MITIGATIONS

None.


# CONTACT US

Note: Keywords labeled as KEY in this document are used for parsing
purposes.

If you would like to receive AIX Security Advisories via email,
please visit "My Notifications":
* http://www.ibm.com/support/mynotifications
* https://www.ibm.com/support/mynotifications

To view previously issued advisories, please visit:

* http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq
* https://www14.software.ibm.com/webapp/set2/subscriptions/onvdq
 
Contact IBM Support for questions related to this announcement:

* http://ibm.com/support/
* https://ibm.com/support/


To obtain the OpenSSL public key that can be used to verify the
signed advisories and ifixes:

Download the key from our web page:
* http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt
* https://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt

To obtain the PGP public key that can be used to communicate
securely with the AIX Security Team via security-alert@austin.ibm.com you
can either:

## A. Download the key from our web page:

* http://www.ibm.com/systems/resources/systems_p_os_aix_security_pgppubkey.txt
* https://www.ibm.com/systems/resources/systems_p_os_aix_security_pgppubkey.txt

## B. Download the key from a PGP Public Key Server. The key ID is:

0x28BFAA12

Please contact your local IBM AIX support center for any assistance.


# REFERENCES:
 
* Complete CVSS v3 Guide: 
  * <http://www.first.org/cvss/user-guide>
  * <https://www.first.org/cvss/user-guide>

* On-line Calculator v3:
  * <http://www.first.org/cvss/calculator/3.0>
  * <https://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

Security Bulletin: Vulnerabilities in bellmail, caccelstat, iostat,
lquerypv, restbyinode, and vmstat affect AIX (CVE-2017-1692):
<http://www-01.ibm.com/support/docview.wss?uid=isg3T1026946>



# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Mon Feb  5 13:19:26 CST 2018 


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





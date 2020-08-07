# IBM SECURITY ADVISORY

First Issued: Wed Jan  8 12:57:55 CST 2020

The most recent version of this document is available here:

* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory5.asc>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory5.asc>
* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory5.asc>

Security Bulletin: Vulnerabilities in tcpdump affect AIX

# SUMMARY

There are vulnerabilities in tcpdump that affect AIX.

# VULNERABILITY DETAILS

## CVEID: CVE-2018-14467
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14467>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14467>
* *DESCRIPTION* The BGP parser in tcpdump before 4.9.3 has a buffer 
  over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_MP).
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/169829> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14463
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14463>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14463>
* *DESCRIPTION* The VRRP parser in tcpdump before 4.9.3 has a buffer over-read in print-vrrp.c:vrrp_print().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/169827> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14464
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14464>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14464>
* *DESCRIPTION* The LMP parser in tcpdump before 4.9.3 has a buffer over-read in print-lmp.c:lmp_print_data_link_subobjs().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/169828> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14470
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14470>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14470>
* *DESCRIPTION* The Babel parser in tcpdump before 4.9.3 has a buffer over-read in print-babel.c:babel_print_v2().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168314> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-10105
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10105>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10105>
* *DESCRIPTION* tcpdump before 4.9.3 mishandles the printing of SMB data (issue 2 of 2).
* CVSS Base Score: 8.8
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168321> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

## CVEID: CVE-2018-14461>
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14461>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14461>
* *DESCRIPTION* The LDP parser in tcpdump before 4.9.3 has a buffer over-read in print-ldp.c:ldp_tlv_print().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168320> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-10103
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10103>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10103>
* *DESCRIPTION* tcpdump before 4.9.3 mishandles the printing of SMB data (issue 1 of 2).
* CVSS Base Score: 8.8
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168670> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

## CVEID: CVE-2019-15167
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15167>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15167>
* *DESCRIPTION* Tcpdump is vulnerable to a buffer overflow, caused by 
  improper bounds checking by the lmp_print_data_link_subobjs function 
  in print-lmp.c. By sending specially-crafted data, a remote attacker 
  could overflow a buffer and cause the application to crash.
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168671> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14466
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14466>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14466>
* *DESCRIPTION* The Rx parser in tcpdump before 4.9.3 has a buffer over-read in print-rx.c:rx_cache_find() and rx_cache_insert().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See yhttps://exchange.xforce.ibmcloud.com/vulnerabilities/168317> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14469
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14469>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14469>
* *DESCRIPTION* The IKEv1 parser in tcpdump before 4.9.3 has a buffer over-read in print-isakmp.c:ikev1_n_print().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168315> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14468
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14468>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14468>
* *DESCRIPTION* The FRF.16 parser in tcpdump before 4.9.3 has a buffer over-read in print-fr.c:mfr_print().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168316> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14881
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14881>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14881>
* *DESCRIPTION* The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_RESTART).
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168312> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14462
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14462>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14462>
* *DESCRIPTION* The ICMP parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp.c:icmp_print().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168319> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14880
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14880>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14880>
* *DESCRIPTION* The OSPFv3 parser in tcpdump before 4.9.3 has a buffer over-read in print-ospf6.c:ospf6_print_lshdr().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168313> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14465
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14465>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14465>
* *DESCRIPTION* The RSVP parser in tcpdump before 4.9.3 has a buffer over-read in print-rsvp.c:rsvp_obj_print().
* CVSS Base Score: 6.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168318> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-16451
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16451>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16451>
* *DESCRIPTION* The SMB parser in tcpdump before 4.9.3 has buffer over-reads in print-smb.c:print_trans() for \MAILSLOT\BROWSE and \PIPE\LANMAN.
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168301> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-16452
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16452>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16452>
* *DESCRIPTION* The SMB parser in tcpdump before 4.9.3 has stack exhaustion in smbutil.c:smb_fdata() via recursion.
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168300> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-16230
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16230>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16230>
* *DESCRIPTION* The BGP parser in tcpdump before 4.9.3 has a buffer 
over-read in print-bgp.c:bgp_attr_print() (MP_REACH_NLRI).
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168307> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2019-15166
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15166>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15166>
* *DESCRIPTION* lmp_print_data_link_subobjs() in print-lmp.c in tcpdump before 4.9.3 lacks certain bounds checks.
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168299> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14879
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14879>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14879>
* *DESCRIPTION* The command-line argument parser in tcpdump before 4.9.3 has a buffer overflow in tcpdump.c:get_next_file().
* CVSS Base Score: 6.1
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168302> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H)

## CVEID: CVE-2018-16228
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16228>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16228>
* *DESCRIPTION* The HNCP parser in tcpdump before 4.9.3 has a buffer over-read in print-hncp.c:print_prefix().
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168309> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-16229
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16229>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16229>
* *DESCRIPTION* The DCCP parser in tcpdump before 4.9.3 has a buffer over-read in print-dccp.c:dccp_print_option().
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168308> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-16227
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16227>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16227>
* *DESCRIPTION* The IEEE 802.11 parser in tcpdump before 4.9.3 has a buffer over-read in print-802_11.c for the Mesh Flags subfield.
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168310> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-16300
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16300>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16300>
* *DESCRIPTION* The BGP parser in tcpdump before 4.9.3 allows stack consumption in print-bgp.c:bgp_attr_print() because of unlimited recursion.
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168306> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2018-14882
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14882>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14882>
* *DESCRIPTION* The ICMPv6 parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp6.c.
* CVSS Base Score: 5.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/168311> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

## CVEID: CVE-2017-16808
* <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16808>
* <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16808>
* *DESCRIPTION* tcpdump before 4.9.3 has a heap-based buffer over-read related to aoe_print in print-aoe.c and lookup_emem in addrtoname.c.
* CVSS Base Score: 7.5
* CVSS Temporal Score: See <https://exchange.xforce.ibmcloud.com/vulnerabilities/134999> for the current score
* CVSS Environmental Score: Undefined
* CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

# AFFECTED PRODUCTS AND VERSIONS
 
* AIX 7.1, 7.2
* VIOS 2.2, 3.1

The following fileset levels are vulnerable:
        
key_fileset = aix

| Fileset | Lower Level | Upper Level | KEY |
| ------- | ----------- | ----------- | --- |
| bos.net.tcp.server | 6.1.9.0 | 6.1.9.401 | key_w_fs |
| bos.net.tcp.server | 7.1.5.0 | 7.1.5.32 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.2.0 | 7.2.2.17 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.3.0 | 7.2.3.16 | key_w_fs |
| bos.net.tcp.tcpdump | 7.2.4.0 | 7.2.4.0 | key_w_fs |
        
To find out whether the affected filesets are installed 
on your systems, refer to the lslpp command found in AIX user's guide.

Example:  

```
lslpp -L | grep -i bos.net.tcp.server
```


# REMEDIATION

## A. APARS
            
IBM has assigned the following APARs to this problem:

| AIX Level | APAR | Availability | SP | KEY |
| --------- | ---- | ------------ | -- | --- |
| 7.1.5 | IJ20783 | ** | SP06-2015 | key_w_apar |
| 7.2.2 | IJ20784 | ** | SP06-2016 | key_w_apar |
| 7.2.3 | IJ20785 | ** | SP05-2016 | key_w_apar |
| 7.2.4 | IJ20786 | ** | SP02-2015 | key_w_apar |

| VIOS Level | APAR | Availability | SP | KEY |
| ---------- | ---- | ------------ | -- | --- |
| 2.2.6 | IJ20781 | ** | 2.2.6.60 | key_w_apar |
| 3.1.0 | IJ20785 | ** | 3.1.0.40 | key_w_apar |
| 3.1.1 | IJ20786 | ** | 3.1.1.20 | key_w_apar |

Subscribe to the APARs here:

* <http://www.ibm.com/support/docview.wss?uid=isg1IJ20781>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ20783>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ20784>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ20785>
* <http://www.ibm.com/support/docview.wss?uid=isg1IJ20786>

* <https://www.ibm.com/support/docview.wss?uid=isg1IJ20781>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ20783>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ20784>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ20785>
* <https://www.ibm.com/support/docview.wss?uid=isg1IJ20786>

By subscribing, you will receive periodic email alerting you
to the status of the APAR, and a link to download the fix once
it becomes available.

## B. FIXES

AIX and VIOS fixes are available.

The AIX and VIOS fixes can be downloaded via ftp or http from:

* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_fix5.tar>
* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_fix5.tar>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_fix5.tar>

The link above is to a tar file containing this signed
advisory, fix packages, and OpenSSL signatures for each package.
The fixes below include prerequisite checking. This will
enforce the correct mapping between the fixes and AIX
Technology Levels.

| AIX Level | Interim Fix (**.Z) | KEY |
| --------- | ------------------ | --- |
| 7.1.5.3 | IJ20783s3a.191118.epkg.Z | key_w_fix |
| 7.1.5.4 | IJ20783s4a.191118.epkg.Z | key_w_fix |
| 7.1.5.5 | IJ20783s5a.191115.epkg.Z | key_w_fix |
| 7.2.2.2 | IJ20784s2a.191118.epkg.Z | key_w_fix |
| 7.2.2.3 | IJ20784s3a.191118.epkg.Z | key_w_fix |
| 7.2.2.4 | IJ20784s4a.191115.epkg.Z | key_w_fix |
| 7.2.3.1 | IJ20785s1a.191120.epkg.Z | key_w_fix |
| 7.2.3.2 | IJ20785s2a.191119.epkg.Z | key_w_fix |
| 7.2.3.3 | IJ20785s3a.191115.epkg.Z | key_w_fix |
| 7.2.4.0 | IJ20786s1a.191120.epkg.Z | key_w_fix |
| 7.2.4.1 | IJ20786s1a.191120.epkg.Z | key_w_fix |
    
Please note that the above table refers to AIX TL/SP level as
opposed to fileset level, i.e., 7.2.2.3 is AIX 7200-02-03.

Please reference the Affected Products and Version section above
for help with checking installed fileset levels.

| VIOS Level | Interim Fix (**.Z) | KEY |
| ---------- | ------------------ | --- |
| 2.2.6.31 | IJ20781sCc.191121.epkg.Z | key_w_fix |
| 2.2.6.32 | IJ20781sCd.191121.epkg.Z | key_w_fix |
| 2.2.6.40 | IJ20781sDa.191121.epkg.Z | key_w_fix |
| 2.2.6.41 | IJ20781sDb.191121.epkg.Z | key_w_fix |
| 2.2.6.50 | IJ20781sEa.191121.epkg.Z | key_w_fix |
| 3.1.0.0 | IJ20785s2a.191119.epkg.Z | key_w_fix |
| 3.1.0.10 | IJ20785s2a.191119.epkg.Z | key_w_fix |
| 3.1.0.20 | IJ20785s3a.191115.epkg.Z | key_w_fix |
| 3.1.1.0 | IJ20786s1a.191120.epkg.Z | key_w_fix |
| 3.1.1.10 | IJ20786s1a.191120.epkg.Z | key_w_fix |

To extract the fixes from the tar file:

```
            tar xvf tcpdump_fix5.tar
            cd tcpdump_fix5
```

Verify you have retrieved the fixes intact:

The checksums below were generated using the ```openssl dgst -sha256 [filename]``` command as the following:

| openssl dgst -sha256 | filename | KEY |
| -------------------- | -------- | --- |
| e8fc68fe0311cd3fe84b29b0a9eda6144d0ddd01f4e4c6326c5d55712a338b88 | IJ20781sCc.191121.epkg.Z | key_w_csum |
| e4da84993d82493efa11b788b31d06fcdddd52fd9b54ec5b9d290a85f1de916c | IJ20781sCd.191121.epkg.Z | key_w_csum |
| 677a27573e419c6060ea0338c37e2bae9989b91fabb5250c8dd8c9145332b016 | IJ20781sDa.191121.epkg.Z | key_w_csum |
| 0a3fac5dd8eea545edd5de813cdcaaedaca88cbf5b1fcd1941271540c3c7424a | IJ20781sDb.191121.epkg.Z | key_w_csum |
| 2970c0240a28f249431988fd9d4b6f37698c132db83174340d1aa5fe496a2ae0 | IJ20781sEa.191121.epkg.Z | key_w_csum |
| 71ef56bd120efb3e8cb0ebda33eed1600a38d3f5b65325b68de1b861d7f3b113 | IJ20783s3a.191118.epkg.Z | key_w_csum |
| 1c86e9cc304c2a7a833dbd92eaf11eb7f575047b27dfe2cca59c52ee7d43d39a | IJ20783s4a.191118.epkg.Z | key_w_csum |
| fdd81d76ffdb700959bb77a2419c7a979a86f0c1eed8a21b7d6a4a3b2ceb885b | IJ20783s5a.191115.epkg.Z | key_w_csum |
| 731c8b73993d94ca74bee8f7fbde9a79cc7e42db87a60aa0c9a9a49b18273382 | IJ20784s2a.191118.epkg.Z | key_w_csum |
| 7c4c366ab91a5a7c1f4ad4fe96fba7bad90accfaa585a1fcdb55fb891bf52345 | IJ20784s3a.191118.epkg.Z | key_w_csum |
| fdcbe85e363e5617abdfb0a0ac4a9bbb5501d133c0eaac72d8a52c6cbf1c6dbe | IJ20784s4a.191115.epkg.Z | key_w_csum |
| 278cf7ac32a11322166d641d49ccf584d17dda5d6b507629fcd69bcf61d72b64 | IJ20785s1a.191120.epkg.Z | key_w_csum |
| 1346d26230f9725a459b46368108489bfbc3a73d4e71e3b14ca9922e995e9b39 | IJ20785s2a.191119.epkg.Z | key_w_csum |
| 51c6fca2564d8bdd4476cc465c2fd22019fb66a87db490a306c17cd4cdd38384 | IJ20785s3a.191115.epkg.Z | key_w_csum |
| 20651d1763eed7a3fe4eb83f5ff0428f5f49cc7be1d2de1b6489a39ab2b5daa9 | IJ20786s1a.191120.epkg.Z | key_w_csum |


These sums should match exactly. The OpenSSL signatures in the tar
file and on this advisory can also be used to verify the
integrity of the fixes.  If the sums or signatures cannot be
confirmed, contact IBM Support at <http://ibm.com/support/> and describe the discrepancy.         
 
```
            openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
 
            openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]
```

Published advisory OpenSSL signature file location:
 
* <http://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory5.asc.sig>
* <https://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory5.asc.sig>
* <ftp://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory5.asc.sig >

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

If you would like to receive AIX Security Advisories via email, please visit "My Notifications":

* <http://www.ibm.com/support/mynotifications>

To view previously issued advisories, please visit:

* <http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq>
 
Contact IBM Support for questions related to this announcement:

* <http://ibm.com/support/>
* <https://ibm.com/support/>

To obtain the OpenSSL public key that can be used to verify the signed advisories and ifixes:

Download the key from our web page:

* <ftp://ftp.software.ibm.com/systems/power/AIX/systems_p_os_aix_security_pubkey.txt>

Please contact your local IBM AIX support center for any assistance.


# REFERENCES
 
* Complete CVSS v3 Guide:  <http://www.first.org/cvss/user-guide>
* On-line Calculator v3: <http://www.first.org/cvss/calculator/3.0>


# RELATED INFORMATION

* IBM Secure Engineering Web Portal <http://www.ibm.com/security/secure-engineering/bulletins.html>
* IBM Product Security Incident Response Blog <https://www.ibm.com/blogs/psirt/>
* Security Bulletin: Vulnerability in tcpdump affects AIX <https://www.ibm.com/support/pages/node/1169974>


# ACKNOWLEDGEMENTS

None.


# CHANGE HISTORY

First Issued: Wed Jan  8 12:57:55 CST 2020


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




# IBM SECURITY ADVISORY

First Issued: Tue May 22 15:30:11 CDT 2018
|Updated: Fri Aug 17 08:05:01 CDT 2018
|Update: Added a link to the bulletin for CVE-2017-5715, known as Spectre, 
|   regarding updated iFixes that are only applicable to some POWER9 systems.
|   The bulletin is available here:
|   http://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc
|   https://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc
|   ftp://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc

The most recent version of this document is available here:
http://aix.software.ibm.com/aix/efixes/security/variant4_advisory.asc
https://aix.software.ibm.com/aix/efixes/security/variant4_advisory.asc
ftp://aix.software.ibm.com/aix/efixes/security/variant4_advisory.asc

Security Bulletin: IBM has released AIX and VIOS iFixes in response to 
     Speculative Store Bypass (SSB), also known as Variant 4.

===============================================================================

SUMMARY:

     IBM has released the following fixes for AIX and VIOS in response to 
     CVE-2018-3639.

===============================================================================

VULNERABILITY DETAILS:

    CVEID: CVE-2018-3639
        http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639
        https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639


    AFFECTED PRODUCTS AND VERSIONS:
 
        AIX 5.3, 6.1, 7.1, 7.2
        VIOS 2.2.x 

        The vulnerabilities in the following filesets are being addressed:
        
        key_fileset = aix

        Fileset                 Lower Level  Upper Level KEY 
        ---------------------------------------------------------
        bos.mp64                5.3.12.0     5.3.12.10   key_w_fs
        bos.mp64                6.1.9.0      6.1.9.316   key_w_fs
        bos.mp64                7.1.4.0      7.1.4.34    key_w_fs
        bos.mp64                7.1.5.0      7.1.5.16    key_w_fs
        bos.mp64                7.2.0.0      7.2.0.6     key_w_fs
        bos.mp64                7.2.1.0      7.2.1.5     key_w_fs
        bos.mp64                7.2.2.0      7.2.2.16    key_w_fs
        
        To find out whether the affected filesets are installed 
        on your systems, refer to the lslpp command found in AIX user's guide.

        Example:  lslpp -L | grep -i bos.mp64

        Note: AIX or VIOS users of all fileset levels should continue to monitor
        their My Notifications alerts and the IBM PSIRT Blog for additional 
        information about these vulnerabilities:

        - My Notifications
          http://www.ibm.com/support/mynotifications

        - IBM PSIRT Blog - Potential Impact on Processors in the Power Family
          https://www.ibm.com/blogs/psirt/potential-impact-processors-power-family/


    REMEDIATION:

        A. APARS
            
            IBM has assigned the following APARs to this problem:

            AIX Level APAR     Availability  SP   KEY
            ------------------------------------------------
            5.3.12    IJ05826  N/A           N/A  key_w_apar
            6.1.9     IJ05824  **            SP12 key_w_apar
            7.1.4     IJ05823  **            SP7  key_w_apar
            7.1.5     IJ05822  **            SP3  key_w_apar
            7.2.0     IJ05821  **            N/A  key_w_apar
            7.2.1     IJ05820  **            SP5  key_w_apar
            7.2.2     IJ05818  **            SP3  key_w_apar

            VIOS Level APAR    Availability  SP       KEY
            ------------------------------------------------
            2.2.4      IJ05824 **            N/A      key_w_apar
            2.2.5      IJ05824 **            N/A      key_w_apar
            2.2.6      IJ05824 **            2.2.6.22 key_w_apar

            The relevant APARs will also be included in 7.1.5 and
            7.2.2 SPs with a build id of 1831 or later.

            Subscribe to the APARs here:

            http://www.ibm.com/support/docview.wss?uid=isg1IJ05818
            http://www.ibm.com/support/docview.wss?uid=isg1IJ05820
            http://www.ibm.com/support/docview.wss?uid=isg1IJ05821
            http://www.ibm.com/support/docview.wss?uid=isg1IJ05822
            http://www.ibm.com/support/docview.wss?uid=isg1IJ05823
            http://www.ibm.com/support/docview.wss?uid=isg1IJ05824

            https://www.ibm.com/support/docview.wss?uid=isg1IJ05818
            https://www.ibm.com/support/docview.wss?uid=isg1IJ05820
            https://www.ibm.com/support/docview.wss?uid=isg1IJ05821
            https://www.ibm.com/support/docview.wss?uid=isg1IJ05822
            https://www.ibm.com/support/docview.wss?uid=isg1IJ05823
            https://www.ibm.com/support/docview.wss?uid=isg1IJ05824

            By subscribing, you will receive periodic email alerting you
            to the status of the APAR, and a link to download the fix once
            it becomes available.

        B. FIXES

            AIX and VIOS fixes are available.

            An LPAR system reboot is required to complete the iFix installation,
            or Live Update may be used on AIX 7.2 to avoid a reboot.

            The AIX/VIOS fixes can be downloaded via ftp or http from:

            ftp://aix.software.ibm.com/aix/efixes/security/variant4_fix.tar
            http://aix.software.ibm.com/aix/efixes/security/variant4_fix.tar
            https://aix.software.ibm.com/aix/efixes/security/variant4_fix.tar 

            The link above is to a tar file containing this signed
            advisory, fix packages, and OpenSSL signatures for each package.
            The fixes below include prerequisite checking. This will
            enforce the correct mapping between the fixes and AIX
            Technology Levels.
            
            AIX Level  Interim Fix (*.Z)         KEY
            ----------------------------------------------
            5.3.12.9   IJ05826m9b.180427.epkg.Z  key_w_fix
            6.1.9.9    IJ05824m9a.180501.epkg.Z  key_w_fix
            6.1.9.10   IJ05824mAa.180501.epkg.Z  key_w_fix
            6.1.9.11   IJ05824sBa.180426.epkg.Z  key_w_fix
            7.1.4.4    IJ05823m4a.180501.epkg.Z  key_w_fix
            7.1.4.5    IJ05823m5a.180430.epkg.Z  key_w_fix
            7.1.4.6    IJ05823m6a.180426.epkg.Z  key_w_fix
            7.1.5.0    IJ05822m1a.180430.epkg.Z  key_w_fix
            7.1.5.1    IJ05822m1a.180430.epkg.Z  key_w_fix
            7.1.5.2    IJ05822s2a.180426.epkg.Z  key_w_fix
            7.2.0.4    IJ05821m4a.180430.epkg.Z  key_w_fix
            7.2.0.5    IJ05821m5a.180430.epkg.Z  key_w_fix
            7.2.0.6    IJ05821m6a.180424.epkg.Z  key_w_fix
            7.2.1.2    IJ05820m2a.180430.epkg.Z  key_w_fix
            7.2.1.3    IJ05820m3a.180430.epkg.Z  key_w_fix
            7.2.1.4    IJ05820m4a.180423.epkg.Z  key_w_fix
            7.2.2.0    IJ05818m1a.180423.epkg.Z  key_w_fix
            7.2.2.1    IJ05818m1a.180423.epkg.Z  key_w_fix
            7.2.2.2    IJ05818s2a.180420.epkg.Z  key_w_fix
    
            Please note that the above table refers to AIX TL/SP level as
            opposed to fileset level, i.e., 7.2.2.1 is AIX 7200-02-01.

            The above fixes are cumulative and include the previously issued
            Spectre/Meltdown security fixes:
            http://aix.software.ibm.com/aix/efixes/security/spectre_meltdown_advisory.asc

            The provided iFixes for 7.1.5.2 and 7.2.2.2 are not required on SPs 
            with a build id of 1831 or later. Please run "oslevel -s" to view 
            installed build id.

            Please reference the Affected Products and Version section above
            for help with checking installed fileset levels.

            VIOS Level  Interim Fix (*.Z)         KEY
            -----------------------------------------------
            2.2.4.40    IJ05824m9a.180501.epkg.Z  key_w_fix
            2.2.4.50    IJ05824m9b.180502.epkg.Z  key_w_fix
            2.2.4.60    IJ05824sBa.180426.epkg.Z  key_w_fix
            2.2.5.20    IJ05824m9a.180501.epkg.Z  key_w_fix
            2.2.5.30    IJ05824m9b.180502.epkg.Z  key_w_fix
            2.2.5.40    IJ05824sBa.180426.epkg.Z  key_w_fix
            2.2.6.0     IJ05824mAa.180501.epkg.Z  key_w_fix
            2.2.6.10    IJ05824mAa.180501.epkg.Z  key_w_fix
            2.2.6.20    IJ05824sBa.180426.epkg.Z  key_w_fix
            2.2.6.21    IJ05824sBa.180426.epkg.Z  key_w_fix
            
            The above fixes are cumulative and include the previously issued
            Spectre/Meltdown security fixes:
            http://aix.software.ibm.com/aix/efixes/security/spectre_meltdown_advisory.asc

            To extract the fixes from the tar file:

            tar xvf variant4_fix.tar
            cd variant4_fix

            Verify you have retrieved the fixes intact:

            The checksums below were generated using the
            "openssl dgst -sha256 file" command as the following:

            openssl dgst -sha256                                              filename                 KEY
            -----------------------------------------------------------------------------------------------------
            fc10d3fcc4b372e54e4f6a88c33a317d7137db4713def21536735bc926c78c68   IJ05818m1a.180423.epkg.Z key_w_csum
            da5f493bd51051336c7528ba8667c8dd9272db4ba06ee5ef9f943c0a2a39baad   IJ05818s2a.180420.epkg.Z key_w_csum
            7ecd8c0ffed9005d771aeaf8309160d55b46c91ff6e9d9cce5516bbb0fc8ef58   IJ05820m2a.180430.epkg.Z key_w_csum
            4e7598e7bc623d850fe1b50503739b0b3cadac08c45fdbe2037d7b4a812bbe08   IJ05820m3a.180430.epkg.Z key_w_csum
            80d4263c0e231c18a752b943f522d71516db850466f820149cd81a0c53b68352   IJ05820m4a.180423.epkg.Z key_w_csum
            1e4ab00e0fd1a7bb4a38cfad30bd021edd0d8106bed9636f62fabbca70d3be65   IJ05821m4a.180430.epkg.Z key_w_csum
            6b5c8a209573f4916cd22f03481b0962e904e24ee993db0e531c68761abb74a3   IJ05821m5a.180430.epkg.Z key_w_csum
            28b2171be5442994394b39410c2db05569223fc3fcff0c552c3b8ddf210f7107   IJ05821m6a.180424.epkg.Z key_w_csum
            42bef3d5dd9d228ab79bd75725de5ce3dc3ef2a28894fa9ca4f47dab3191858e   IJ05822m1a.180430.epkg.Z key_w_csum
            5e6be49f5563f5a89d4ecc5ea5c52e06ac9f7c7749b9b217ba3abf34bb4a49b8   IJ05822s2a.180426.epkg.Z key_w_csum
            686bd91a387df1043c38ddc0dfe1409223145ad8f8d335d52e0341c0bcb91de1   IJ05823m4a.180501.epkg.Z key_w_csum
            79fce1a11262f192c869b67742eb47f92e354f0c7b25c191043b46be442f4ad1   IJ05823m5a.180430.epkg.Z key_w_csum
            dc013e5f65263db7bd2cb35efa29dffacfe886996d072b459f51d22cdf646a2f   IJ05823m6a.180426.epkg.Z key_w_csum
            5cd8fc8e3fe0bc2f2deab5956a13e2045580af9d98b56bbe606f4f87403b5ffd   IJ05824m9a.180501.epkg.Z key_w_csum
            1b6f28af977841e1f2f08dcfa26edb20974d4ea0b51d2f08c1108331a2c8b625   IJ05824m9b.180502.epkg.Z key_w_csum
            95ac10d417ad9a4017b5b9057b0937189721f260c94bb71969e4fabd33f5a539   IJ05824mAa.180501.epkg.Z key_w_csum
            4fa9372d4137265fef88aeb5af36dc1745467cc9f35deb01e6c850ea67b06b66   IJ05824sBa.180426.epkg.Z key_w_csum
            4b4dc4961f3a27cd6774ce37bf980ded29cbd962031014e067e117ce0b474c53   IJ05826m9b.180427.epkg.Z key_w_csum

            These sums should match exactly. The OpenSSL signatures in the tar
            file and on this advisory can also be used to verify the
            integrity of the fixes.  If the sums or signatures cannot be
            confirmed, contact IBM Support at
            http://ibm.com/support/ and describe the discrepancy.         
 
            openssl dgst -sha1 -verify [pubkey_file] -signature [advisory_file].sig [advisory_file]
 
            openssl dgst -sha1 -verify [pubkey_file] -signature [ifix_file].sig [ifix_file]

            Published advisory OpenSSL signature file location:
 
            http://aix.software.ibm.com/aix/efixes/security/variant4_advisory.asc.sig
            https://aix.software.ibm.com/aix/efixes/security/variant4_advisory.asc.sig
            ftp://aix.software.ibm.com/aix/efixes/security/variant4_advisory.asc.sig 

        C. FIX AND INTERIM FIX INSTALLATION

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

            http://www14.software.ibm.com/webapp/set2/sas/f/aix.efixmgmt/home.html

            To preview an interim fix installation:

            emgr -e ipkg_name -p         # where ipkg_name is the name of the
                                         # interim fix package being previewed.

            To install an interim fix package:

            emgr -e ipkg_name -X         # where ipkg_name is the name of the
                                         # interim fix package being installed.

    WORKAROUNDS AND MITIGATIONS:

        None.


===============================================================================

CONTACT US:

    Note: Keywords labeled as KEY in this document are used for parsing
    purposes.

    If you would like to receive AIX Security Advisories via email,
    please visit "My Notifications":

        http://www.ibm.com/support/mynotifications

    To view previously issued advisories, please visit:

        http://www14.software.ibm.com/webapp/set2/subscriptions/onvdq
 
    Contact IBM Support for questions related to this announcement:

        http://ibm.com/support/
        https://ibm.com/support/

    To obtain the OpenSSL public key that can be used to verify the
    signed advisories and ifixes:

        Download the key from our web page:

    http://www.ibm.com/systems/resources/systems_p_os_aix_security_pubkey.txt

    Please contact your local IBM AIX support center for any
    assistance.


REFERENCES:
 
    Complete CVSS v3 Guide:  http://www.first.org/cvss/user-guide
    On-line Calculator v3:
        http://www.first.org/cvss/calculator/3.0


RELATED INFORMATION:

    IBM Secure Engineering Web Portal
        http://www.ibm.com/security/secure-engineering/bulletins.html

    IBM Product Security Incident Response Blog
        https://www.ibm.com/blogs/psirt/

    IBM PSIRT Blog - Potential Impact on Processors in the Power Family
        https://www.ibm.com/blogs/psirt/potential-impact-processors-power-family/

    Security Bulletin: IBM has released AIX and VIOS iFixes in response to 
    Speculative Store Bypass (SSB), also known as Variant 4.
        http://www-01.ibm.com/support/docview.wss?uid=isg3T1027700

|   Security Bulletin: IBM has released updated AIX and VIOS fixes for 
|   CVE-2017-5715, known as Spectre, that are only applicable to some POWER9 
|   systems.
|       http://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc
|       https://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc
|       ftp://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc

ACKNOWLEDGEMENTS:

    The vulnerability was reported to IBM by Google Project Zero.


CHANGE HISTORY:

    First Issued: Tue May 22 15:30:11 CDT 2018
    Updated: Wed Jun  6 14:56:44 CDT 2018
    Update:  Additional iFixes are now available. 
        Additional iFixes are now available for:
            AIX 6100-09-09 and 6100-09-10
            AIX 7100-04-04 and 7100-04-05
            AIX 7100-05-00 and 7100-05-01
            AIX 7200-00-04 and 7200-00-05
            AIX 7200-01-02 and 7200-01-03
            AIX 7200-02-00 and 7200-02-01
            VIOS 2.2.4.40 and 2.2.4.50
            VIOS 2.2.5.20 and 2.2.5.30
            VIOS 2.2.6.0 and 2.2.6.10
|   Updated: Fri Aug 17 08:05:01 CDT 2018
|   Update: Added a link to the bulletin for CVE-2017-5715, known as Spectre, 
|       regarding updated iFixes that are only applicable to some POWER9 
|       systems.
|       The bulletin is available here:
|       http://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc
|       https://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc
|       ftp://aix.software.ibm.com/aix/efixes/security/spectre_update_advisory.asc


===============================================================================

*The CVSS Environment Score is customer environment specific and will 
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





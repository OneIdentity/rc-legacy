VASIDMAP project has been **Discontinued**. For help on how to integrate Samba and Authentication Services see: [KB316264](http://support.oneidentity.com/authentication-services/kb/316264)


# vasidmap
One Identity Samba Identity Mapper (**vasidmap**) provides Samba servers with accurate identity information for Unix-enabled Active Directory users to ensure proper file system access controls for Samba servers that are joined to an Active Directory domain. Vasidmap plugs into Samba's idmap interface, resolving queries for user security information by using One Identity Authentication Services' (QAS) Active Directory connections and caches. vasidmap should be used with all installations of Samba where QAS is installed — especially for servers using Authentication Services' Unix personality management feature.
## Quick Installation Instructions
1. Ensure that you have Samba installed; **we recommend using at least version 3.3.16 of your operating system's Samba package**. The One Identity ID Mapper should work with samba 3.0.28+ but versions below 3.3.16 are not supported.
2. Ensure that the host is joined to Active Directory (vastool join)
3. Install quest-vasidmap
4. Run the vas-samba-config script:

`# /opt/quest/sbin/vas-samba-config`

and answer the questions asked.

Please see the installation guide for detailed instructions and troubleshooting.

## FAQ
Q: Will the **vasidmap** work with Samba packages from my operating system vendor or compiled from source?

A: Yes, both. **vasidmap** was designed to integrate with Samba to provide additional benefits to customers using Samba and Authentication Services together. Please make sure you are running at least version 3.3.16 of Samba before using the **vasidmap**.

Q: What are the benefits of using **vasidmap** with Samba?

A: **vasidmap** can be used on servers that are accessed by Unix-enabled users via both local (shell) access and over Samba/CIFS shares. Using the ID mapper ensures file ownership matches the user's Unix-enabled attributes. **vasidmap** should not be used where non-Unix-enabled users access shares because it does not allocate IDs to non-Unix-enabled users. In that case either the idmap_rid or idmap_tdb providers should be used instead of **vasidmap**. See the Samba HOWTO chapter on identity mapping for further information.

## Compiling
Compiling the vasidmap package from source requires the Authentication Services SDK to be installed. The SDK can be found in the SDK subdirectory directory of the Quest Authentication Services Installation CD.

Run the following in the main directory:
```
./configure
make
make package
```

If the 'configure' script doesn't exist, make it using the 'autogen.sh' script.

If 'pp' doesn't understand your system and can't create a package, you can 
try installing the software directly with:

    make install

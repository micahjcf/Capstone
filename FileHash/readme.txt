FileHash -icheck [ icheck_options ]
-or-
FileHash filepath [ options ]

This utility calculates the hash value of a given file using the MD5,
SHA-1 and MFA-256 cryptographic hash algorithms.  Calling this program with
no arguments displays this help.

The -icheck option runs test vectors to verify algorithm implementations

icheck_options:
-sha            verify SHA1 implementation
-md5            verify MD5 implementation
-mfa            verify MFA implementation
-v                      verbose mode (default only shows PASSED/FAILED text)

options:
-sha            calculate SHA1 hash value
-md5            calculate MD5 hash value
-mfa            calculate MFA hash value
-v                      verbose mode
-beep           Beep once done (useful when hashing huge files)
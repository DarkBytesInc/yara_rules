rule Win_Spyware_Banker_288
{
strings:
	$a0 = { c340521144b89d6b0bd3c53dca61b8a77ce50e9b4ae2e391674026e2f35bb9bef3c74617edc3474b7015ba24ebb255460a4089d001c547a2b5a4f5744bbab2a1ee6bb90e770ef13943c2947befaec787c68f8ca6fd24bccb8c50ebf5aa7fdd72c72a455c2b2840521072aa25ac7f0da9ea238c49fadeb2d4721f80aa8d30abfe72fcdfc510715c387adff45a3cade9524d26d40d8fb2 }

condition:
	$a0
}

        
rule Win_Spyware_Banker_6099
{
strings:
	$a0 = { aa2cc3bdec1e952a629c2b89114d2cf88e21b0a7908faed4e32893c7fd763856e7fa8dc6c5ff2cb8d9f299386fdd708f065b53fa99ed365649a63dad2d045264d19d7b3a5fd18ca1ae1542830411b0002b04a4bf59f29a6da7d8d57ab3c42654bc1d19c9e9d452c18106b312df4bf9d307f3f4a19c334bf81b405b2ef32803820f286bff }

condition:
	$a0
}

        
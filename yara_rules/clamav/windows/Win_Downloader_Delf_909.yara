rule Win_Downloader_Delf_909
{
strings:
	$a0 = { efe8ba4ebe0ae816eebaa7390cfc18243891f2a272607aaa487b51779d2bf98b66b697b1c22c10fd1fb8c22278767d8ecbd7783900dbcffb1f0d3ffaee70d1ed19c90abcb0b3fbc01b9672ed2b7e6ffc99ed6bd45d343d607854e7b1b5f6d942e62100c6 }

condition:
	$a0
}

        

rule Win_Downloader_Swizzor_408
{
strings:
	$a0 = { bae9dccffcf1f6b67be02d3e28a75efa0a1b7d2795b37b4c56bcca2b5965a31afd9a59bec5925acf8d1d14deaf86fdb6e135653f1c993ea2f27b7bd1cbb681b1b98802b1702fe2a1f75dbf73901c4b81f5dd109205901eda6e80 }

condition:
	$a0
}

        

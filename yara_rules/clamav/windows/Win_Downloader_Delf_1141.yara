rule Win_Downloader_Delf_1141
{
strings:
	$a0 = { 0cb2d004db392e7e639b9f1e5a5c7bb3f5749b5fea2e9ac4e1d95d02653d89c743654466d3cd8fa276bfc590da7402105c6e52e4dc6e44b0219a77272a626ad276cf6598791aae2493e8d1798c1281bb30 }

condition:
	$a0
}

        

rule Win_Downloader_Banload_82
{
strings:
	$a0 = { 33c05568537f400064ff30648920b8b4984000ba687f4000e8a8b7ffffb8b0984000e84ab7ffffb8a89840008b15b4984000e88eb7ffff68fe00000068a8974000e8d3c6ff }

condition:
	$a0
}

        

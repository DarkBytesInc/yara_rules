rule Win_Downloader_Agent_35028
{
strings:
	$a0 = { 96ee0a0fde2ba00569dc27c06cebacebf21e55c512e9ece9eff7181f3d1ed5f7f2f517f5c0d3d00f2d1e39c0c2dc3bfef25e8fa8dd8235c01d381722ce1bc5fdc8c131fbf2ce7bb422fe32ddcb870af1d3a04168b5c1c084ef8448083afd }

condition:
	$a0
}

        

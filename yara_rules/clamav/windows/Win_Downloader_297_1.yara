rule Win_Downloader_297_1
{
strings:
	$a0 = { 35513da8a8db7bdc06e233667a0d0a0378dee45b4db83aef70eca6e46d8392b0fb6fe32888224e7f74c4fb961b3f1d5ce4865f514b97b07d61e04dbcfa802c57e68df908cf9a7e2b0bd3e07cebcd59b32dec8623c56f8132d221 }

condition:
	$a0
}

        

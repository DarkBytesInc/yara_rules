rule Win_Downloader_954_1
{
strings:
	$a0 = { b52e960ee27bd251a4729830edbb68e0ecbaa6e427e165ac14ff4f4db3b5841a90be3d4a8c1e684193fd1d3fa477e4a36b703e7cdcfee2b67f03877448f440056a15d2b144b8380c635c1aec900e7ee27cb5061dd2ce164f9ea6efe1 }

condition:
	$a0
}

        

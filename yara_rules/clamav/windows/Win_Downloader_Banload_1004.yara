rule Win_Downloader_Banload_1004
{
strings:
	$a0 = { 9033324166f83581835c585274b179ac1af8d425e4a97cee6b78fc2663d92ba2d231fb434a871276f445032b14b9a14bec13dbb43ebd267d3ca9b33d79e3405c18794e95b63e3fedde88f2b440f68aaa }

condition:
	$a0
}

        

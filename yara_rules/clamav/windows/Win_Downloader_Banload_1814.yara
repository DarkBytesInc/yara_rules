rule Win_Downloader_Banload_1814
{
strings:
	$a0 = { ffead5ffffead5ffffead5ffffead6ffffead6ffffead6ffffead6ffffead5ffffcbb5ff9c6f6cff0000008f0000002f00000000bb9c460feccc7bffe6c26bb5cfad540300000000caa542acf0cc52fff7d34ffff6c742fff2ba37fff0b231ffe09e28ff9a6a29ffa9 }

condition:
	$a0
}

        

rule Win_Downloader_Delf_1126
{
strings:
	$a0 = { c0742a6a008d45f0e8f9fdffff8d45f0ba2cff4100e86c40feff8b45f0e85c42feff50e8c660feffe855feffff33c05a595964891068d1fe41008d45f0ba04000000e89b3dfeffc3e97537feffebeb8be55dc3000000ffffffff0a0000006566323665 }

condition:
	$a0
}

        

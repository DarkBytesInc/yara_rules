rule Win_Downloader_1007_1
{
strings:
	$a0 = { 67648d8dbe5c3b4c471fb0148888dee6c4cdd17e4087c8cad64672f5c013f0447eac4682a2930d76f5b27e9f7f831bd409c6cc81c348c2ce85910d9f89f9ccd884f9f68bba9614cd368adbf59a5d2eeadac9862b6aec7ec882fe2247 }

condition:
	$a0
}

        

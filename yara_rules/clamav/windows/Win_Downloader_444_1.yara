rule Win_Downloader_444_1
{
strings:
	$a0 = { ff8b8523fdffffa32879011080c23ab6edc6859bfbffff6d80e927c6859afbffff6180cd1ac68592fbffff65b17780ee52c68593fbffff74b5e180e188c68596fbffff6180c5c1c6859cfbffff6580c2e7c68597fbffff73c6859efbffff0080e65dc68591fbffff47 }

condition:
	$a0
}

        

rule Win_Spyware_Banker_3442
{
strings:
	$a0 = { dafde4e8a90fb9d4a72ab1bb8894710425fb6bc3a95bfec8695abfd66994a8c3d62e952afdebb1a143736c419d4e18182687fae5f2a8b5b4b4df6925b696db3dc6b088f741665036ff987bb57ef82f593b8a61deb2d849a7739548bd7a1882 }

condition:
	$a0
}

        

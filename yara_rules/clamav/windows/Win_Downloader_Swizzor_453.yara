rule Win_Downloader_Swizzor_453
{
strings:
	$a0 = { 8ddc062ef6d1b74478b059a77f33c1792df8c1bda31b97c43f02b71164710daea27f8b82578513e29d8e369e438e2ce0a2c9157ae8cca7c211f7ac3a54022e802ef7bebd01ca39d7cb06bd560391b4e5ab98f21a12724b5ecc88 }

condition:
	$a0
}

        

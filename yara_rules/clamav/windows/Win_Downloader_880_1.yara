rule Win_Downloader_880_1
{
strings:
	$a0 = { b38d8a03a4926a3abed8bc052fc3d862711dd6819ccfafebe924bedef8dfe514008bad93ed226fd6ea2b07df3bcdd1ddec1589c1d0d95440903b371bd7865962d0f8e7bac3e62e4b56046bfe653bac28c72063b07472d6753ec47bd8 }

condition:
	$a0
}

        

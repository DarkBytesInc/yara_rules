rule Win_Downloader_Zlob_2310
{
strings:
	$a0 = { 738eef8105159f40e34f8df3cfdc7eb38e421101e647fa033e021a30912e910dd325152b092eda6d1f88845ddb7a947a6387ca348e3aa0b9e8aa8c8ac8d723019e1d449894197c31c0a0a4e6a3c9 }

condition:
	$a0
}

        

rule Win_Downloader_Banload_635
{
strings:
	$a0 = { 51faa6ef3ab0e75e119c543b0649ee2c06eb05e6af3634ba1fb3528f535ff3d2674810dfa28cd148d6aa52f80f40e7bb4a389036da44fb42af801cdf02a941e0f6f99fec03c72cddb56947890b428bf9202925233bfac4b1e1e5 }

condition:
	$a0
}

        

rule Win_Downloader_Zlob_1736
{
strings:
	$a0 = { 319b7dc343a7bd095be67987d72a3fa4749705dd3848fe3cf8e0e90f1f8cb32e7c85b79f2cdee3adfc197240f247193978fe1b7338766e17f5683ec95d0f95d4453b6e9d1315b6a95b389c82b26d }

condition:
	$a0
}

        

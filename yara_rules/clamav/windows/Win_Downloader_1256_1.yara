rule Win_Downloader_1256_1
{
strings:
	$a0 = { bd4efcffff83c7088b0789850efcffff80f2358bbd4efcffff83c71089bd4efcffff80edb380ed548bb54efcffff66833e087502eb0ab800000000e91617000080c5558bb54efcffff83c608833e007402eb0ab800000000e9f91600008bbd4efcffff83c7088b0789859afcffff }

condition:
	$a0
}

        

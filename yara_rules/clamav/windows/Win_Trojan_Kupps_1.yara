rule Win_Trojan_Kupps_1
{
strings:
	$a0 = { 8ec326813e00029c51742bbe030103360101bf0002b9d700f3a426a1840026a3d00226a1860026a3d20226c70684 }

condition:
	$a0
}

        

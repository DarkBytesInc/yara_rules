rule Win_Trojan_V_74
{
strings:
	$a0 = { 0e1f8c062c00e863007206e83200e83c002e8e062c00061fba8000b41acd218cc00510002e01062e002e0106360058 }

condition:
	$a0
}

        

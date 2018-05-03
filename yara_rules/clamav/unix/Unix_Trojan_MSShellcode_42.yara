rule Unix_Trojan_MSShellcode_42
{
strings:
	$a0 = { 996a0f5852e80c0000002f6574632f736861646f77005b68b601000059cd806a0158cd80 }

condition:
	$a0
}

        

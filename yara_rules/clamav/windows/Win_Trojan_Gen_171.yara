rule Win_Trojan_Gen_171
{
strings:
	$a0 = { 38005589e5e8d0febf61020e57b8370050bf500d1e579a42002c00833e100e007527803e650d107414bf6e0d1e }

condition:
	$a0
}

        

rule Win_Trojan_Rip_1
{
strings:
	$a0 = { 0300a3010132c033d2e84100b90300ba0001e85900b00233d2e831008d940301b92e01e84800e8 }

condition:
	$a0
}

        

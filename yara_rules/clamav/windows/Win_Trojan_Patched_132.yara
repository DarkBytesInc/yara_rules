rule Win_Trojan_Patched_132
{
strings:
	$a0 = { 6068f3????00ff15??????0061e9????ffff743332646d2e64617400000000 }

condition:
	$a0
}

        

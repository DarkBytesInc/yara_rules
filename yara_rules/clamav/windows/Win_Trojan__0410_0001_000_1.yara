rule Win_Trojan__0410_0001_000_1
{
strings:
	$a0 = { 2d03008986bb00b440b9b8008d960300cd21b000e81b00b440b903008d96ba00cd215a5983c9 }

condition:
	$a0
}

        

rule Win_Trojan__0412_0001_000_1
{
strings:
	$a0 = { 222d03008986d000b440b9cd008d960300cd21b000e81c00b440b903008d96cf00cd215a5983c9 }

condition:
	$a0
}

        

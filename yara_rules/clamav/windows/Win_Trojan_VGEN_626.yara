rule Win_Trojan_VGEN_626
{
strings:
	$a0 = { 9a0000c6009a000044005589e5b800019ab502c60081ec0001c6063523039a2d13c600bfc4001e578dbe00ff165731c0 }

condition:
	$a0
}

        

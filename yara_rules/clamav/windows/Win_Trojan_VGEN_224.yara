rule Win_Trojan_VGEN_224
{
strings:
	$a0 = { 9a00004b005589e531c09a7c024b00e88cfdb801009ae9004b005d31c09ae9004b0000000000000000000000558bec83 }

condition:
	$a0
}

        

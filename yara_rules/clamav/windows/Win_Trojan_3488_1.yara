rule Win_Trojan_3488_1
{
strings:
	$a0 = { 0400052a2e6578650d48656c6c6f2c20776f726c64219a00001d005589e5b800019acd02 }

condition:
	$a0
}

        

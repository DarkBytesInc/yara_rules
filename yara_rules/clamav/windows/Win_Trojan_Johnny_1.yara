rule Win_Trojan_Johnny_1
{
strings:
	$a0 = { 12806a0e4e4149504553564f48205245484d }
	$a1 = { c2806a10476c6f62616c3a76476f6a6f686e6e79126903647324076a0a3a76476f6a6f686e6e79 }

condition:
	$a0 and $a1
}

        

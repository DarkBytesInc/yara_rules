rule Win_Trojan_Trivial_554
{
strings:
	$a0 = { 8bfec3e8????ac2ac132c1d2c0aaff0e????833e????0077 }

condition:
	$a0
}

        

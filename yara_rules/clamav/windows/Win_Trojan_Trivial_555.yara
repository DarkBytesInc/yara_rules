rule Win_Trojan_Trivial_555
{
strings:
	$a0 = { 89f7c3e8????ac2ac132c1d2c0aaff0e????833e????0077 }

condition:
	$a0
}

        

rule Win_Trojan_Happy99_2
{
strings:
	$a0 = { f2f5d1f2f5ff5a45524f070000000d0a626567696e2036343420486170707939392e6578650d }

condition:
	$a0
}

        

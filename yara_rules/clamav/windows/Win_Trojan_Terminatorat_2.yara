rule Win_Trojan_Terminatorat_2
{
strings:
	$a0 = { 558bec6aff6868414000685031400064a1000000005064892500000000 }
	$a1 = { 5468617420697320612074657374 }

condition:
	$a0 and $a1
}

        

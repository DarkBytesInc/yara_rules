rule Win_Trojan_Katusha_2
{
strings:
	$a0 = { 0031c8b9130f0000018dacfeffff218d20ffffff09c121c14131c848018504feffff31c081c0fe000000218544feffff8985e8feffff018528ffffff81e8000c00004081f8c10a0000761d8b55941995fcfeffffff8df4feffff85d2720a29d081e80013 }

condition:
	$a0
}

        

rule Win_Trojan_Pakes_988
{
strings:
	$a0 = { 6033c0502dd29b9393502dc0ee023a502d0001fdd0508bc46a006a0050e8????????83c41083f8017c1066b950450340 }

condition:
	$a0
}

        

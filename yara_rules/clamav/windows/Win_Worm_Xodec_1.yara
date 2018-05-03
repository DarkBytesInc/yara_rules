rule Win_Worm_Xodec_1
{
strings:
	$a0 = { c745fc070000006818734000680c754000ff1554104000 }

condition:
	$a0
}

        

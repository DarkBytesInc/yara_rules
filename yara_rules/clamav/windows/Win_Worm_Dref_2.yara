rule Win_Worm_Dref_2
{
strings:
	$a0 = { bde844000033ed68fa54400060e90ebbffff9050ff156c1c40006affff15601c4000ff25307040 }

condition:
	$a0
}

        

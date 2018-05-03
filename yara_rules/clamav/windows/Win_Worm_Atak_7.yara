rule Win_Worm_Atak_7
{
strings:
	$a0 = { 5068060002006a0068546040006802000080ff15085040 }

condition:
	$a0
}

        

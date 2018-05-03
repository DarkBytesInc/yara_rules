rule Win_Worm_Kido_110
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833de0630110 }
	$a1 = { a92cf96eb5594fcc685262455a08845d }

condition:
	$a0 and $a1
}

        

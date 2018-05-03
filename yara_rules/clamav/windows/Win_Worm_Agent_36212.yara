rule Win_Worm_Agent_36212
{
strings:
	$a0 = { 55505821 }
	$a1 = { 505249564d5347202573203a5b }
	$a2 = { 656e746869636174696f6e2070617373776f726421 }

condition:
	$a0 and $a1 and $a2
}

        

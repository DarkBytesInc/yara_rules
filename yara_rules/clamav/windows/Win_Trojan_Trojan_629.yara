rule Win_Trojan_Trojan_629
{
strings:
	$a0 = { 7461696c202d[2-4]202430207c207461696c202d72207c2075756465636f6465202d6f }

condition:
	$a0
}

        

rule Win_Trojan_Agent_34208
{
strings:
	$a0 = { 817dfc8f0100007e1d8b55f8b8c0784000e841ccffff85c07e0ce8c8d3ffffc680090000000133c05a595964891068b0784000 }

condition:
	$a0
}

        

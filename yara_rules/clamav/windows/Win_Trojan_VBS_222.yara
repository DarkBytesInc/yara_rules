rule Win_Trojan_VBS_222
{
strings:
	$a0 = { 756a2e636f70792864726f6761646f73797326225c6f7074696f6e732e766273 }

condition:
	$a0
}

        

rule Win_Trojan_Diehard_1
{
strings:
	$a0 = { 666f726d617420633a202f78202f71 }
	$a1 = { 5c737461727475705c6469656861726464726976652e626174 }

condition:
	$a0 and $a1
}

        

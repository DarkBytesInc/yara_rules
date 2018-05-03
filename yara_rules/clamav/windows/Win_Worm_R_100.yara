rule Win_Worm_R_100
{
strings:
	$a0 = { 20202f2e74696d657220312031202f6a6f696e2023526f6d616e7469632d446576696c2e52 }

condition:
	$a0
}

        

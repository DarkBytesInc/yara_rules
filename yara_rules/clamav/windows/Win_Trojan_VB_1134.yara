rule Win_Trojan_VB_1134
{
strings:
	$a0 = { 6c69440072636d68736569646c652e65785300666f }
	$a1 = { 726569736e6f525c6e75 }
	$a2 = { 7274635c002a002a2e6d00697373007465707569 }

condition:
	$a0 and $a1 and $a2
}

        

rule Win_Trojan_mem_2
{
strings:
	$a0 = { b81101f6c32075023407f6c30c75023470f6c340750380f407f6c31075022473f6c78075022470 }

condition:
	$a0
}

        

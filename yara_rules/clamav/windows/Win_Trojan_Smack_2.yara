rule Win_Trojan_Smack_2
{
strings:
	$a0 = { ad000a00584c444154412e584c4d200040002500ca0101002800d40125006700ad005300584c6b }

condition:
	$a0
}

        

rule Win_Trojan_Small_4072
{
strings:
	$a0 = { 6a006a006a00e80000000083c41056535557eb13e82f00000085c975f7eb61e8520000005950c3 }

condition:
	$a0
}

        

rule Win_Trojan_Small_4074
{
strings:
	$a0 = { eb0a595e5b5d5fe8240000006a006a006a00e80000000083c41056535557eb13e82f00000085c975f7eb49e8d2ffffff5950c3 }

condition:
	$a0
}

        

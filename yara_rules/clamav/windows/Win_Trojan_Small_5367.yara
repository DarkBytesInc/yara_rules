rule Win_Trojan_Small_5367
{
strings:
	$a0 = { e80000000083c404e80000000083c404e80000000083c40468aeb1c01d59515860615850 }

condition:
	$a0
}

        

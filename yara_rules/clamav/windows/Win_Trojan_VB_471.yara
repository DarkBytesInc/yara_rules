rule Win_Trojan_VB_471
{
strings:
	$a0 = { 726d0d0121816f7765722d5370792076312e3220dbffdfb6420757002e49525043444f542e43 }

condition:
	$a0
}

        

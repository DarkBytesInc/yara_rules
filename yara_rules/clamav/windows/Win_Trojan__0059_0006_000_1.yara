rule Win_Trojan__0059_0006_000_1
{
strings:
	$a0 = { 33f681c50001e88701b440b9c1045acd21b80042e84000b440b90400ba2003cd21b801572e }

condition:
	$a0
}

        

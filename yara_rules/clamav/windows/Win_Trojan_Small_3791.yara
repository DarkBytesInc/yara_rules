rule Win_Trojan_Small_3791
{
strings:
	$a0 = { ee0759becaca65410e1b44847bc644d0d2cb84026c1ea913307b59be475fb228495eb81ca5611c13d3f2aa0f9b5cb049c50edc235006e405840920cdfe4e5f431190a6bac645e66e500759bed24c }

condition:
	$a0
}

        

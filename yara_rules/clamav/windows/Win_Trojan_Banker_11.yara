rule Win_Trojan_Banker_11
{
strings:
	$a0 = { 5c0005556e69743100008bc0ffffffff12000000696e7373363040676f676f2e636f6d2e62720000558bec81c4fcfeffff5333c08985fcfeffff33c05568 }

condition:
	$a0
}

        

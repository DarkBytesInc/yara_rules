rule Win_Trojan_Proxy_91
{
strings:
	$a0 = { 7465720049440000636f6e66696700005c70616172732e696e6900005b626c61636b6c }

condition:
	$a0
}

        

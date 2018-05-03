rule Win_Proxy_Ranky_38
{
strings:
	$a0 = { 6e69782e6e65742f622e7068703f0000006376626466676400255573 }

condition:
	$a0
}

        

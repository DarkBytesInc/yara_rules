rule Win_Proxy_Lager_13
{
strings:
	$a0 = { 66c7440af4000068d616400052ff15ea10400085c0740a8b45f9a333144000eb05 }

condition:
	$a0
}

        

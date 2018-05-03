rule Win_Proxy_Lager_52
{
strings:
	$a0 = { 3691b40d5f06228ded938828153acc9f2cef32ec3b03876ce2d75f1795f830b722777934bc7b70d09a6985333eebb796e000baaf8ac5c36341861cad7a0fbc39a338ee00db3b }

condition:
	$a0
}

        

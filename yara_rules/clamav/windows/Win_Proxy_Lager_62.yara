rule Win_Proxy_Lager_62
{
strings:
	$a0 = { 1d04006ab1180608be6eaef0bd04eea22f8736efade003276dbe0e09c6b80b77af84046fd847d94bd33c79b2ac5f29ffe95906105ad37f9f36aa698aad6859015f099cc37b58 }

condition:
	$a0
}

        

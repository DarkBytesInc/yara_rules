rule Win_Trojan_Lineage_373
{
strings:
	$a0 = { a9db9b26bf40f21f54dc766d12fe761419ee520f3383df5fdb4469833dce46a173563f54421ec3838a7e88f605cd443b85098280d5eed5b6bf1d964fc4bc2a70a57b6f6c7f51edd7b36ebcdeed643cb121fbbedafa1ce5ac8698ae42a72f408f326ce1e1e6c2720ce211e486 }

condition:
	$a0
}

        

rule Win_Trojan_SdBot_2311
{
strings:
	$a0 = { 1406246a5acee5cb947f1d82acb5e8f3176b5f43c93ac8dc3b1d4554d6609d7672ba9db8156b8feca152ec6b03d791a13c25d7ffdfb5b090304c14ec1fee1c9b919157ded17f82f7c2bb31108c28eac6e16f4023f7 }

condition:
	$a0
}

        

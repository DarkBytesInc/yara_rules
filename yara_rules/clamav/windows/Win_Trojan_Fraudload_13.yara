rule Win_Trojan_Fraudload_13
{
strings:
	$a0 = { ff098e8cc0ffffffe1eee6ffff1b8e28c8fffff3f8b2e8ffff4a458bfbc2effffff18e3cc0ffff85fb2ae2ffff51bbece5ffff9dce01bbeb6875e2ffff037ea4c3ffff34e4971169f8e8ffffe59721b452c5fa76fd888d38c1ffff75e08aecffff2986fc }

condition:
	$a0
}

        

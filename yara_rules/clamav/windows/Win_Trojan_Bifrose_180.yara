rule Win_Trojan_Bifrose_180
{
strings:
	$a0 = { ff685b520b4f1fc224b403c531bff0e0e9170700fefcba9c75832deb748af4f57cee001e4211b32559dd9009063bb59803b656dfe10177e0823000f3b0325a05e1e66e03 }

condition:
	$a0
}

        

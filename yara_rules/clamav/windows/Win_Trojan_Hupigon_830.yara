rule Win_Trojan_Hupigon_830
{
strings:
	$a0 = { 1e242db3d54519cf831a433fc081bfc6f9a23dabd7e9e3af27923d0ad842f2a863b8c62b6a754e7245409e5104fb6fd83cfb463fae3dc5280caa26b4c0fe2c65c6abcdb5c897ae1c0e82e87030acb0b04c4fb1553b2394f12e5ab87894a8ab }

condition:
	$a0
}

        

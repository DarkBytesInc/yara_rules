rule Win_Trojan_I13_3
{
strings:
	$a0 = { fd00bde2052e8a4d24f8f8f5f8fcf880f13df6d19080f13d2e884d24474d75e533741332ed7491057e12fafecc3f7127e1f8417bff40bffd46fbff0c5bf1f1e0f8470010ca0135726957fd326f4b747f }

condition:
	$a0
}

        

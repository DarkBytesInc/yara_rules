rule Win_Trojan_Bancos_2052
{
strings:
	$a0 = { 1efd9a1016fc0a0ac7ed177b9b20f0cdd7fdfe9aef00c6e1fa37a8e5e3957bff19b6c5fbc47521f9ae42859a357c4730d2029306e908ab3ac9bad4f4d23e879226697c608deca6d2dd2a55173a516a58b87ddcf6c758e75f }

condition:
	$a0
}

        

rule Win_Trojan_SdBot_2345
{
strings:
	$a0 = { e0e3bf802e9ddead76b7806a8b66aa64e4405c83f623fb1e85a1ed6ac0c11f35a0efefd714871d4d03c180e0704ae24a132f72ab76af32d732eedc825721fefc5fcae7ca3a82a13e21ba0faec3a1e40025d6df4e03 }

condition:
	$a0
}

        

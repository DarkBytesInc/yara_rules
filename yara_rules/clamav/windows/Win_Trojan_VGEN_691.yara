rule Win_Trojan_VGEN_691
{
strings:
	$a0 = { 09baab01cd21b82135cd21891e22018c062401b82125ba0301cd21b80031ba1900cd210d0a53797374656d20696d6d }

condition:
	$a0
}

        

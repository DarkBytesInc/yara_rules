rule Win_Trojan_Philis_98
{
strings:
	$a0 = { 0f00e66003d72bd7e8000000000f00e7608bf303fe615ab80a010000565781f6875c000081f7682500005f5e56 }

condition:
	$a0
}

        

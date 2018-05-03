rule Win_Worm_Iksmas_6
{
strings:
	$a0 = { 558bec03f881c1d2aeb7ab81e10f0a409481d67617209c8bf98bca81de90a01f }

condition:
	$a0
}

        

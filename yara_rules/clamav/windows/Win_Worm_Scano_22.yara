rule Win_Worm_Scano_22
{
strings:
	$a0 = { ec3a5edd8609d66ea9b5479cfa21ad2490bab0700e3b72c85a270884a8b62c2d92714d150995c5ff1a1e3f6b7995c1ab }

condition:
	$a0
}

        

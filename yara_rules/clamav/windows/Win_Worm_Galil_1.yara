rule Win_Worm_Galil_1
{
strings:
	$a0 = { 68617665206e6f7468216e61207361792009f8df8a62d67374216c6c205a6143f6d4ff7b7620216c04c0889006e010f726 }

condition:
	$a0
}

        
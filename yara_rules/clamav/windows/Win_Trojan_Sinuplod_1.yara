rule Win_Trojan_Sinuplod_1
{
strings:
	$a0 = { 792054727573747c4c65737306232e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e060c2d2d20426574612033202d2d061a7e20 }

condition:
	$a0
}

        

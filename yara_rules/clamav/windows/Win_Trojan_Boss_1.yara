rule Win_Trojan_Boss_1
{
strings:
	$a0 = { 48656c6c6f20426f7373203a292000426179203a282000225c5e5f5e2f22005f40235f005e5f5e002a2e2a0000 }

condition:
	$a0
}

        

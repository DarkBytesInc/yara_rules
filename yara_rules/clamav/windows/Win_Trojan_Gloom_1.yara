rule Win_Trojan_Gloom_1
{
strings:
	$a0 = { 485348494654005f5f4148494e4352002e2e5c2e2e5c544553545c474c4f4f4d2e4300474c4f4f4d0073636e4275660061780062780063780064780073690064 }

condition:
	$a0
}

        
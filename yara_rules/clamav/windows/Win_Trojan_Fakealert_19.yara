rule Win_Trojan_Fakealert_19
{
strings:
	$a0 = { bb5fe9d3a614abd1b00f4ec7a2591ffd6beede01e351a3428a4065b9974cd4dde849aac3e9a0e2e1f26e4e900707665aeb1011fa68462f37e91db6f168cf023e3675eeb9fb987ca0e682dbf568245ed37784ea42e81189eb7c9c69de33144b528ce9c5c5 }

condition:
	$a0
}

        

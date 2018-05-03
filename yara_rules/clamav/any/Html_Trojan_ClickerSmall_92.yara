rule Html_Trojan_ClickerSmall_92
{
strings:
	$a0 = { 75702e6578653fc56bff9ffb2e00650078030063616d706169676e5f47c77ec3fb00494541430700570049004e }

condition:
	$a0
}

        

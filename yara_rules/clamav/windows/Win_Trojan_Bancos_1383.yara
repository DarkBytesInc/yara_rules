rule Win_Trojan_Bancos_1383
{
strings:
	$a0 = { 0414e3692168b8f055930b4043a9604c8333fc90e03ae5b1f7bf1c13574534dbafb13ebea50a3c79a6373a6dc9b5da131b802361ff4be89fe048dd7a3ba80d28f335af839dbed5dd8cef8df7bc32748e29be2ea7fa0365e1ed37e1b05164a643a1aa5f7bf82d38e8 }

condition:
	$a0
}

        

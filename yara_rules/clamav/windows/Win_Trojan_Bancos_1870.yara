rule Win_Trojan_Bancos_1870
{
strings:
	$a0 = { b3ac7f9961b2501cc4ebb5b032de8eac9d66103e727a2c1c30a9a76798126d62a4ceb87f51915ca63b0ab21a8e8a8177943693bec567143ca357992d5d03dac4d0c5956901cd }

condition:
	$a0
}

        

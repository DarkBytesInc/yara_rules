rule Win_Trojan_Bancos_650
{
strings:
	$a0 = { 733802f7fa191ddeb00c128f3edccfbb9be5873c29320cf2bfe07e64d27d52afaafc717fa58924d6ef934526a1118642006dd7c220f8f0c2d7cb614bf81ac90fb2e50be74bfffc4f67e167539744e49c79dae1dea5e4e72eca26 }

condition:
	$a0
}

        

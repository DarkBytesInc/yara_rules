rule Win_Trojan_Agent_33055
{
strings:
	$a0 = { c56e8b8eea81f030f60dbf4052243a88d84438bd124855c2c4022a856460d2bdd784890db734ebd8ce16083ce38841285414e3091fc00b089ca5226e635b5fab16125c8d013d7eaeb9438122a019 }

condition:
	$a0
}

        
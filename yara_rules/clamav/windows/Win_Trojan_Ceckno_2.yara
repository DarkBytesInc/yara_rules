rule Win_Trojan_Ceckno_2
{
strings:
	$a0 = { 83ec10538b5c24185633f657566a016a02c703000000008974242cff15f49240008bf883ffff0f84860000008b4424246a25c1e00466c744241002008b884cb44000894c2414ff15d49240008d54240c6a105257668944241aff15f092400085c0753d558b2de4924000 }

condition:
	$a0
}

        
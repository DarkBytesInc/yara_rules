rule Win_Trojan_Small_3688
{
strings:
	$a0 = { b7b4216bf7dc9c903fdfc9783418d12e480b8928e1b6c82bdf34da38b7892109b4dcc9fb73c4360c93c4366dbfcc8978e8829423ee1f9f2fdfdcd978b7b6c187a2e4d938b78c366d8bcc89783c2ca378ddff9f12b723dc2ca79cc9fd77a8fbf38aecd938b78a36af321cbd5de1231ef8cbec36 }

condition:
	$a0
}

        

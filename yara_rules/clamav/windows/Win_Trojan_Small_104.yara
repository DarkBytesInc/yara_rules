rule Win_Trojan_Small_104
{
strings:
	$a0 = { 302541e0ccd35ea03777eb3eff7d1be480474eb4decced500e8d57a17d65f5e11100d7a5ce994c737425a751936b052f2cbb9b937dc797671c40f8d17c28f885bb220db71251156f6899253949f16ac597a170e0e7c9ba5b6c9bf781e1659f9744be0415a89458fdeac06aa090d8a959d26b6f093abdb44982e82afa208e50ec66c7634524fd9b7f736d6d1a4875f399c31eb84f7da6 }

condition:
	$a0
}

        
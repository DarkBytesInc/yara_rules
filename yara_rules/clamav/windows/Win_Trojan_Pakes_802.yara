rule Win_Trojan_Pakes_802
{
strings:
	$a0 = { cf086da073681174be86c64f54e416c94fa506336b11a1984f1d61482a1fcb0150ce0c4590fc34d70428cc4ed416535a435d216f316cca5864525d4e45bac92ea8180865541dd8c81b1a199b854a3a6a1e6dcdda5aab21510f7d0cfd60fe469fc719c0bf85668a9c64b236b261896831cf4145102d9653e5908034087b103467357a4126c604604f3d99bd4f }

condition:
	$a0
}

        
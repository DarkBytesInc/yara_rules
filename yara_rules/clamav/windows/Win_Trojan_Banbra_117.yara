rule Win_Trojan_Banbra_117
{
strings:
	$a0 = { aca925a963df9dca3903fec6f3b7a24792707fe76297ad628448e2dc8597a2114c2096c7d74428d6af99ea174889a55f3a45745f877f9245a34f6d715d3d29ea3e7e744b878f1e6806ef9bde96ef14769b4255c8cb9205fd5dca303ab45db24a63e7029cb2024c4e0b4ec7751d31 }

condition:
	$a0
}

        
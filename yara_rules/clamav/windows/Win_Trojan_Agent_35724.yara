rule Win_Trojan_Agent_35724
{
strings:
	$a0 = { 0ae0ac388068352025bf6ab0ee0f1dde107acf8254e17904ec3ffda451a901631fa91e01028bfc81c72090b0e75f555399ed382062fb7b47fdefe803dfc130cb1f06094bf73fd35bbfddf403035c241081c3874d48f08d9f0a993ff2a72f0a0205a2d5c003da33d9544b8ee3608a148d9be5b30a28808bdc89296412c1014e33e32be1dcc423784c0fe78d20 }

condition:
	$a0
}

        
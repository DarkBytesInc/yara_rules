rule Win_Virus_Expiro_26
{
strings:
	$a0 = { 50519052905390545556575589e583ec68c745f809000000c745ec04000000c745e80d000000c745f0????????c745c8????00008b75c881c6????0000bb????000081c3????000081c6????????81c3??????00eb128b45e883e80d8945f4c745d000??????eb05ff4df0ebe98b45e80345f889c783ef1339df73358a043e88 }

condition:
	$a0
}

        
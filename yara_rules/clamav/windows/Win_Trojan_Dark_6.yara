rule Win_Trojan_Dark_6
{
strings:
	$a0 = { 6f023d6a0c633a6461726b736964652e63233b34716c01006436716c0100126a15576f72644d6163726f2e4461726b53696465312e4364 }

condition:
	$a0
}

        
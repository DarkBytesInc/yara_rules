rule Win_Trojan_Lineage_61
{
strings:
	$a0 = { 2020202020202020202020202020202063630053568bf0bb050100008bc68bd3e80000255c538bc6e80000248450e800002aa08bd88bc68bd3e80000255c8b06807c18ff5c740c8bc6bab86d4000e8000022345e5bc300ffffffff010000005c0000005356 }

condition:
	$a0
}

        
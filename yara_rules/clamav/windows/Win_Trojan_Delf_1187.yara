rule Win_Trojan_Delf_1187
{
strings:
	$a0 = { 35684d1a04ddd1ace7e084a27036b3ddac85cf430432689443ce1e9cc83c0ed413026f6041698f75604008b6268ac85bc8782e60d6203836715053c4ce8b900ad526eeb0b7962da3c4baec668b0cd8877201d258eb0598019f9b8c8515252d0b42456a24387937ffff2f472a644531707530715a53644e7a356c50754e3066f5b7faff52354d4f482f437037614948783c7942556546 }

condition:
	$a0
}

        
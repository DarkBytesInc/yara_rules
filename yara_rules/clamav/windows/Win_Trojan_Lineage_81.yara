rule Win_Trojan_Lineage_81
{
strings:
	$a0 = { 0e10566edd2c3dcf254f4645727c4a596464e4917a4a6ea808107201f1e44172cef3b517c1de199e6db68cca77ae9ecc8c30db1582034afaf7b990ef6e657f19c57a4f7f642218d8c8afb75d43b6b79764cef2cf02eb6df9a4c93739f6746a683050748203ad453d01846e4c6c23948c35bb465daae8ed264dc8c833c925cec22277c8f73b273298767a13163eac677bcfe75a7afa }

condition:
	$a0
}

        
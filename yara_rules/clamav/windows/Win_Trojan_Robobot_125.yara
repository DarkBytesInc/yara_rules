rule Win_Trojan_Robobot_125
{
strings:
	$a0 = { 650462da603c8f25a022396fa69397641217dba2cbec9b4411d24396db831907fcc219bc25d7062e1c61a10917e06bc749f7491d061fe521c1865f2bc115e11f30a6a1a5b99b5b95b3ccf1d0b0225ee7691cfbece6346d9c96ea21b273b47ae335c17066f826c02da62ebbb5d6f236acc11a7a2a960f3f487be4d1f61425f625926a4a6462ba312c2e7856afafb7e3b531f4ce06f80b }

condition:
	$a0
}

        
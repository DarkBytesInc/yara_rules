rule Win_Trojan_Lineage_309
{
strings:
	$a0 = { da45d466b01f4235d4a558926da6720281aacd924c21920cf0cbcb892261525f74964eb96bdd860e56be130ca960b0ec3a2787d7507faa7d39b2c7416f9ccbbe48aa93c98529307dcb240ef3eda10b3ebeac6ec14c6f07bd3863edff }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_8499
{
strings:
	$a0 = { fd4d69eb6eeeba24f5352f565fa6b87fd3524d10ac439162f515a6bb50cd1ca28292e700e414f6d906fbbce678c2f7cb40b8bff0ebc5bad237cddd62ab30740cb966742c654cee6e2934f39bb721e0f3347bdfb9bd }

condition:
	$a0
}

        

rule Win_Trojan_SdBot_2136
{
strings:
	$a0 = { da287fdaa78707075e7f8b566f3bb70784a04cccdeaeff698d29cabf7c19212eff1197d4300b71476931cdc0eb37f65f39b4514f6b0d154fbfa0a9e7c9816c9170fd9479d0af9bd8fc85408c8e936456f74a40e130dbfcc7e7e6 }

condition:
	$a0
}

        

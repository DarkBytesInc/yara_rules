rule Win_Spyware_Banker_5854
{
strings:
	$a0 = { fc8b4030508d45c0508b45fc8b48348b45fc8b50300fafd78b45fc8b40340fafc3e8abbcfcff8d45c0508b45f8e82fc8fdff508b45f4e826c8fdff8d55d059e8917afdff8b45fc8b4030508d45c0508b45fc8b48348b45fc8b50300fafd78b45fc8b40340fafc3e865bcfcff8d45c0508b45f0e8e9c7fdff508b45ece8e0c7fdff8d55d059e84b7afdff8b4dec8b }

condition:
	$a0
}

        
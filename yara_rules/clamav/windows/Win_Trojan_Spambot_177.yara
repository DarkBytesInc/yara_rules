rule Win_Trojan_Spambot_177
{
strings:
	$a0 = { 11ee74a379dc89a9f4d6ff0ff0ff4208166b625272689364c7e8d107e3aee1374c0fc0ab2a7f02faffed56f4124027df50d67d0b74b649b83eb7ffffffffb799714012cca054f2d520e0313ac958ce34cad20761ebd463ed58aad9a1a236ffffffff4967d2c1dc3c669cf293f212 }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1205
{
strings:
	$a0 = { ab451b3f9b415c38d9edece4d1bdf87c44d1a68bf95b902778a447490cd09ba69a85bb5aa5c3430114681c922750492cf4cf9e77cceafd670babbb3b60d8676597dfca6d7862f1ecefe67ca2a9dadf01116594d338de4afef6f48d529cd29d }

condition:
	$a0
}

        

rule Win_Spyware_Banker_2725
{
strings:
	$a0 = { 33c04cf8bf58d613a819c7403cf71eaab1fda183d52cb8ad58a5988c86157860318da2d410eb170b5fc9e6ae198645f29d01752618d136c0d1806e7cb21ee41335a01fcb25364b34484bdbabe4b8 }

condition:
	$a0
}

        

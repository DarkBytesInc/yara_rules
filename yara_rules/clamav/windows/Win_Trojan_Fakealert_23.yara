rule Win_Trojan_Fakealert_23
{
strings:
	$a0 = { 99fe7b9f83fdc9768d257812def689a71bc15b8000fa9721a047a586e502ac669a3c15fee2b63cd81509bf1fd6ad4b63dc25cff3dd3ee278b69517f6491ad5678db1fb074ee31662fafacd9775bcffaaf4f24ebfd6fcee69d45f91a5eb6cf8196852f6ae }

condition:
	$a0
}

        

rule Win_Trojan_Dyfuca_22
{
strings:
	$a0 = { 699aa65b300334201814d32c9ba61008f8e0e4d04dd3345dc00bb0a89c90442579c8ff59465543415f53490000454e076cf6bf074f }

condition:
	$a0
}

        

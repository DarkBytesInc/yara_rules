rule Win_Trojan_Small_5332
{
strings:
	$a0 = { 40bd3cebad683d37056e7d699ec0a17a621d52257a01ab8f7b00b183d703157a0595a376cdfea8b0f7b0d48a82a8dc6cb6ab183431f157aa43329f21f9e7ded582a9512505ef4db088db232841e2 }

condition:
	$a0
}

        

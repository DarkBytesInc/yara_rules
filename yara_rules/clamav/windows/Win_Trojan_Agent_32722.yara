rule Win_Trojan_Agent_32722
{
strings:
	$a0 = { 1077a8cfa897a85dc13733592e48f527bb07188063dd8de5470caee85ff2edc1c0a67b7b57b741dad45971778907840d0b2ef3a1785a8d11f704c54761a98db394ef38cf0ea01d430c70faec0e0effa4aa1fb03cd6 }

condition:
	$a0
}

        

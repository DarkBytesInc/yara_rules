rule Win_Trojan_Neuroquila_3
{
strings:
	$a0 = { faba????fd????00fd8cc88ed801178bc381c30200b44dcd21d1ca98b8????f7d803c3f5fd7305b8????ebe1 }

condition:
	$a0
}

        

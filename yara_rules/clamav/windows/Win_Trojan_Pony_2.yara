rule Win_Trojan_Pony_2
{
strings:
	$a0 = { cd213d333d75058d5652ffe2b82135cd21899e97008c8699008cc8488ec026a103002b86280326a303008b86 }

condition:
	$a0
}

        

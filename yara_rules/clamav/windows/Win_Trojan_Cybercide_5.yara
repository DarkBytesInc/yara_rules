rule Win_Trojan_Cybercide_5
{
strings:
	$a0 = { 5db822ddcd213d333d75058d567cffe2b82135cd21899e8e028c869002b80935cd21899ec0058c86c205b81c35cd21899e93078c8695078cc8488ec026 }

condition:
	$a0
}

        

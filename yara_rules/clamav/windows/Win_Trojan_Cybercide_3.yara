rule Win_Trojan_Cybercide_3
{
strings:
	$a0 = { e800005db822ddcd213d333d75058d567cffe2b82135cd21899e8e028c869002b80935cd21899e9e058c86a005b81c35cd21899e71078c8673078cc8488ec026 }

condition:
	$a0
}

        

rule Win_Trojan_Hacdef_20
{
strings:
	$a0 = { 756fdbde019bea51f6c5a5e0cda487ab8eb82513cd1187761ab6fba9355b5a686b3a8b00789aea4fec9a224c179a5ae2e115cf0c06ddbd4688e0515f5f77a7ad797339206c1423f63de8b773c8324a7ddfbb41e75020170385aa022d }

condition:
	$a0
}

        

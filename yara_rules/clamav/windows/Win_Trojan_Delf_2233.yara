rule Win_Trojan_Delf_2233
{
strings:
	$a0 = { 5bc6420f00680401000068cc664000e864f9ffff68cc664000e862f9ffff6a01e863f9ffffa1ac504000c60001b800434000a3f8674000c705fc674000b440400068f8674000e8b5f9ffff33c05a595964891068f8424000c3e91ae7ffffebf8e887ebffff000000564741444f574e }

condition:
	$a0
}

        
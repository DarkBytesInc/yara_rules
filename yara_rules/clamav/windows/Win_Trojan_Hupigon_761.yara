rule Win_Trojan_Hupigon_761
{
strings:
	$a0 = { 8dabb9b50475af700dc178a34352638e90511f0730b176bf0376cd7006d2dd465a2bad3cf90b2da7707a7d7e8285fd61d6056246e35f526def010a816c1f332216bd78f7c5b393faaa82bae49ba4 }

condition:
	$a0
}

        

rule Win_Trojan_Lineage_326
{
strings:
	$a0 = { 60f2f47637762ba45ff2dec27ddbe8bfd64983a8918a6995e44af5596d8bfe762eddb3fe425d740e428f7aec77adb926dd68d15d5d4d08b4380b45ca3c97e556a78b202dffa1772150a10cd152395fbbaf6202a3caaa6f41603c23791eb2da }

condition:
	$a0
}

        

rule Win_Trojan_Predatordrop_1
{
strings:
	$a0 = { 0633edb8fd50cd133d50fd74728cc08bd8488ed8a103002d7601726380fc10725ea3030003c3a312008ec033ff8edf832e1304060e1fe800005e81ee3900b9a9 }

condition:
	$a0
}

        

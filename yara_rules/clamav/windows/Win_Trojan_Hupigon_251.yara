rule Win_Trojan_Hupigon_251
{
strings:
	$a0 = { 92f4ccbeefb5dcdbe4bb95b727cb0b92fd50647a63fd545f3b37e06f73b612a097ad2cad9a3ec61c366415e1c4524c71783e2e930a363522c95bf6a6a56fd96aae00222bfd9f90f899647efdffbdcc7580cf7834839c7fd16fd6f53c5568f0b51e10ce3d2a8088034c }

condition:
	$a0
}

        

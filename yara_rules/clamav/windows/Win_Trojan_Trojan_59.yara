rule Win_Trojan_Trojan_59
{
strings:
	$a0 = { 6751ded6525a7af1e2634f719fd90532c0657d95320c16e7ccecb468c08433344bdf567464b924c6faa94e2f3fdc6a8c260f62a3b5731209e2f131c3fee0bd256d904733cba5d1369ecc74ae86147aee }

condition:
	$a0
}

        

rule Win_Trojan_Oggo_1
{
strings:
	$a0 = { 01a20a16617f515698334bac05910a2f610b51521e72106a5201a20a16617f795698334b09ae5550 }

condition:
	$a0
}

        

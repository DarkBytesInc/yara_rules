rule Email_Trojan_Trojan_799
{
strings:
	$a0 = { 6920736565206d792073656c662076657279206d756368207365787920616e6420617474726163746976652e2e2e616e6420696d2066756e20746f2062652077697468 }

condition:
	$a0
}

        
rule Win_Trojan_Small_3868
{
strings:
	$a0 = { 8bf588f10ee1002710d17cf783f58cd43beabc6c65b9206c0ed1d6f0cf2a8cf1b0d27c6c0e07d1854fd1d354690b7d6c68563dc683ea7ba247eabc6c65b9c5a60fd1d5f1cf2af27379d265e010d17c6b442996ac0f28659c49 }

condition:
	$a0
}

        

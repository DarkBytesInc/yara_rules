rule Win_Trojan_Mybot_5883
{
strings:
	$a0 = { 1498247075de703d0a47dc22c4a846d9a4bd96268cc95b36b5907d5cc06b1cfc563a413be1b723a41eac23687bfe28dc86cf3976c3a134f82a5ffc93e0b7243d831269b49acf5ddd3e085e2bd93f8a00a3b3907e453b9744711379a7e6153d38808e0e40a0fcd9132bef67949d2b41607a937722ad5f469a0952b0e21e82c25a6df767656430acfe0a0155d49902dfc1c41c819d8c2c }

condition:
	$a0
}

        
rule Win_Trojan_Spambot_226
{
strings:
	$a0 = { ffe8ffff1369bebf6992d4e869f5213c9692196f89ae3acd3b5e1de60adcffffffffbffdc9bc2b36099f1fcd9782d7ce7e442d6a8b34f74a60f4cee6d2c5cddc55e6ff3ff8fff293153d652b3ef8740abae849295a1cc8cb1cb2bc315e65bc4dffffffff6eb9d0b8a3510af39546 }

condition:
	$a0
}

        

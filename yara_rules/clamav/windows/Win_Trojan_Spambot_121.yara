rule Win_Trojan_Spambot_121
{
strings:
	$a0 = { e51c2e4765f41b81fbb60e3ad1facda58de329020eb0ffff4fff85e2341d2be268b0cf0f2fd802b329a603da5dca0b3529be6feeffd712fee70ff8d46ac5df2ff591742e7d6e076f0f88ffffff3e6f42d50566ddc6dcbda17f200f6f7919b07ddc24cbf44da3fd8bff7f77580a31 }

condition:
	$a0
}

        

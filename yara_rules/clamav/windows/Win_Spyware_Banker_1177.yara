rule Win_Spyware_Banker_1177
{
strings:
	$a0 = { 8fd5a171461bf24ec600fe59d64c44570fa050ca24d60f152d537199ff5524f67afcbea23a88ace23265e3eadea6ee4e9c61d66863dc2ecead1c5525f9582daa792b47cdcf60a262de946b398667e2cfee2b6e5598f99368e82b }

condition:
	$a0
}

        

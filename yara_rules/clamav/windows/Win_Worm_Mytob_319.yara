rule Win_Worm_Mytob_319
{
strings:
	$a0 = { 7df4b404d72ff0609de27cf892a9f2c4e7c118a193ee5f78b1ecafe53a0d7e9e20d9b00ed9a782ebe686f7d729a4a9eacc87921fe81b873dc7101f21ef30dcb2bcf8ea979ef7df16ad37265cc11bcc36bee7d0f35e753c7e2c98a1610c2c2f04 }

condition:
	$a0
}

        

rule Win_Spyware_612_2
{
strings:
	$a0 = { ad4fc4b153b0acdd9c4cbaa6baa0e8b552d862e846a3c47baea6bf5dd7f4acb53accf1a141587b4bad4fc4350fa4bf5d9f4e534a3a7e50a341d8a8b452b0c47fa9a6bfdd91a2b8a63a30f1a141d8d9e846a3442f11b0acbe92c4b8dd85edb8a63a7a57 }

condition:
	$a0
}

        

rule Win_Trojan_SdBot_4034
{
strings:
	$a0 = { b2dc04acf7cf12ee6185b460fb730eebc07fed724abf79c78ea1a3ecabf5fa19375c1d8f8914640c10ff81cb142d34feba3b553877c09d2cb75013c01d61ca4d070f654df2a7e53459db2a4c08a71e22b32a1014c72e }

condition:
	$a0
}

        

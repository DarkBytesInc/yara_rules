rule Win_Worm_Koobface_18
{
strings:
	$a0 = { 633a5c77696e646f77735c743535667425646634342e646174[0-47]613232313030382e636f6d }

condition:
	$a0
}

        

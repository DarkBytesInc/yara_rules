rule Win_Trojan_Hupigon_869
{
strings:
	$a0 = { fe2177b7b0bcf8ebbaad3b0f3bdb7778c9f6259e9bbb21fb81fbb41736ed464f37baedfe1af126f61e9c41a2adc3bab9de1ef6b80ee21336b59f12928c557b639a31196c373102365d5d4c24802e7ac5bc33b2801516ea321ffd615be8edd8 }

condition:
	$a0
}

        

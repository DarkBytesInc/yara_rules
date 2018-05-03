rule Win_Worm_Rxbot_1
{
strings:
	$a0 = { ab72787ddfe8fe246f772c2542ca7e006b57000016a3525617386b71fa170004341887fee200b17826c1a1fe7e000395 }

condition:
	$a0
}

        

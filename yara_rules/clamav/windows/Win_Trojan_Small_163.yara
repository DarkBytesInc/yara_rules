rule Win_Trojan_Small_163
{
strings:
	$a0 = { 01b9b800be0014b8ff4bfccd2133db8ec387f7bffc02f3a4061fbe8400b840038704abad938704ab0e0e1f07ebd0585703f7f3a4cfb442515233d28bcacded5a59c380fc4b756efec074e3fec87566505351571e52b80043cded51b80143 }

condition:
	$a0
}

        

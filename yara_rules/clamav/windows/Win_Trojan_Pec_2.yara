rule Win_Trojan_Pec_2
{
strings:
	$a0 = { 32eb2166c3a1388c5d2ff8a85603f361be10bbd0a50ccf4c83102685388d5d7d5ebb3abaf4e15320413ffbe802fbd028a6bdebfa383e8aaacc47eee93850bcefee9f59cd28bfc1b2a2b757a83e9f49565f8ab37cabbd432fc55435fd6fe14d4ac38b5859150aae56d5758a216d3cd0 }

condition:
	$a0
}

        

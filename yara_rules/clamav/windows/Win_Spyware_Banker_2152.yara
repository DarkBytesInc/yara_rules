rule Win_Spyware_Banker_2152
{
strings:
	$a0 = { b0e45b237a1116e7be3c8eb8ee3bddd6f5e360fb66d64b1a191a704d635a45837ff471a57640c09a90300882dd5c8f41eccee58c611a2eb4d459b7c2bfd4ce1effabc8bb175ecdf0c4b86412df87a06eaec259bb0ecb97ed4a60fae7a5f7ebd4ceafeaace5daf3911431634a2ce672e5ec2b }

condition:
	$a0
}

        

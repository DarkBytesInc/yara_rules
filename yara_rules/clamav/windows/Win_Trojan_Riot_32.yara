rule Win_Trojan_Riot_32
{
strings:
	$a0 = { 5a5233c933dbcd217303e98200b8023d8bd6cd2172de8bd8b43fb904008d960501cd213e80be08011a74c93e80be05014d74c1b8024233c933d2cd213d00fd77 }

condition:
	$a0
}

        

rule Win_Trojan_IRCBot_272
{
strings:
	$a0 = { 11628fa3b8442d002b211bb1f6696a2eba62676a44c8d99bfa2bf497d871a0d54d8bcbb195f1e97de208c954501a567e0e01a384859d000c523365ab60c450dc791e427f5234b577bcea69b89ddeba11 }

condition:
	$a0
}

        

rule Win_Trojan_Lamah_1
{
strings:
	$a0 = { 5d81ed0c013ec686190101b800003d01007503e994013ec686190100be380303f5bf0001a5a4ba840303d5e8050132 }

condition:
	$a0
}

        

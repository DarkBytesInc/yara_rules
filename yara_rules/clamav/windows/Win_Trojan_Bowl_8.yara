rule Win_Trojan_Bowl_8
{
strings:
	$a0 = { 81ed06013ec686130101b800003d01007503e9bb02e8a702e88c021be3a3362425a8937f269a25248081a8b31e21 }

condition:
	$a0
}

        

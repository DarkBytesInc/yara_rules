rule Win_Trojan_Bowl_7
{
strings:
	$a0 = { 81ed06013ec686130101b800003d01007503e9b902e8a502e88a020ff7b7223031bc8769328e31309495bca70835 }

condition:
	$a0
}

        

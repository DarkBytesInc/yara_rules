rule Win_Trojan_Vgen_100
{
strings:
	$a0 = { 63686f206f66660d0a6563686f20477572750d0a70617573650d0a0d0a406563686f206f66662520477552752042 }

condition:
	$a0
}

        
rule Win_Trojan_Commed_1
{
strings:
	$a0 = { 313f3f3f67313f683f3f313f6a3f3f3f3f21743a6774383f743f3f3f21663a743f3a743f313f3f3f3f3f21203f3f3f753f3f213f3f213f3f6c3f21 }

condition:
	$a0
}

        

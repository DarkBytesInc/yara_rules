rule Win_Adware_Zango_6
{
strings:
	$a0 = { 7453686f7070657220536f66747761726520446576656c6f706d656e74204c74642e0000536d6172742053686f7070657220496e630000005a616e676f000000426c696e6b7800005069 }

condition:
	$a0
}

        
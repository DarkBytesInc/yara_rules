rule Win_Trojan_W_53
{
strings:
	$a0 = { b90001000033c0f3ae750cbec1090000bf0000f077eb0abeb9090000bf0000f7bf03f589bd6c0c0000ba00000400fcb9080000005657f3a65f5e740a47 }

condition:
	$a0
}

        

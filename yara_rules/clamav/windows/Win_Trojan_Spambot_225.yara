rule Win_Trojan_Spambot_225
{
strings:
	$a0 = { ac77098cab7656c4ff7ff5ac500f6d1762dcc97b695b5c9845c984dabeeccfffffff4b7d9b09306198b1e364aa9328a8c01178a2d0c5ad2283c8ffffffffa5b401b1c660e2b0ea8448dce4d571c6d6331b2d0a9496f436b5e672096ab4326f09f8ff2c0e5764944948fd85bae118 }

condition:
	$a0
}

        

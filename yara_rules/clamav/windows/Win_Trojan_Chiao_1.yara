rule Win_Trojan_Chiao_1
{
strings:
	$a0 = { 6772017380000c6a012e127362020c6c0000646712806a1a2a2a2a2041206e6577207374617220697320626f726e202a2a2a6467f30064677a007386000c6a027a3164 }

condition:
	$a0
}

        
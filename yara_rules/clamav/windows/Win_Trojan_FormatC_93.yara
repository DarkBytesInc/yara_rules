rule Win_Trojan_FormatC_93
{
strings:
	$a0 = { 6679636f6e6a726f626c73736d696a626d64204064656c74726565202f7920633a5c646f7320 }

condition:
	$a0
}

        

rule Win_Spyware_Banker_5877
{
strings:
	$a0 = { f16d98de5c384d89e05c02c96f53ee7eb31955c34440a52acd7422904121bb98968afec6db0839c76f443c827531cb3fc036bd8621b085ed278833c65d9d8a3ba14916f5 }

condition:
	$a0
}

        

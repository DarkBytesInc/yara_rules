rule Win_Adware_Aspy_1
{
strings:
	$a0 = { 1ebb3d342b991b4853505957b162af58ae4907f3ad1507f97049f70c3bcc557435224516b18822226d6bd1b6de3190e122053a1babf641130c9481d02d662322396640e7742be9e25c66cd11ab84b56ed1d0a83d448ed866a8b8993a92e175735ae506b7616fe63c8dd438cd637a64068c00efe54bfd2080050874703a2f2f772e5de0d565137934452efb1653de2f603bc298706870 }

condition:
	$a0
}

        
rule Win_Trojan_Agent_33551
{
strings:
	$a0 = { 1ce6622c4e386f86d57a47b381bfd50e4cfcaf32d86bd1ef928f6a7bf317aeda5dc46e0ba31444f9e3a66a899483d0f41afb843a652329619faa3df1eef49cb6c1e7baf3180ca1aef72c1ca273d18c4ad413c866b7d0cc1c6c7da752d444b9ef668cf2aaa5d142109eb58c63 }

condition:
	$a0
}

        

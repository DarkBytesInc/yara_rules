rule Win_Trojan_Small_3810
{
strings:
	$a0 = { 4d58cb7a381d3f5fc499ba3ad9e4cb7a381d475fd099ba3ac128dfd63d94bac7c6d8bf3a381d3f5fcc99ba3ad904cc7a38214f5fe899ba3a89e643bf5c3cc03a389392c8bed8c03a3821475fe89aba3a88e5b912c628df1c4194baa278b0fa3a8a9392c67cb8cec3bcb85e40389445c1149cba }

condition:
	$a0
}

        

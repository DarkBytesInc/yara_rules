rule Win_Trojan_Agent_32636
{
strings:
	$a0 = { 478b2c3e2a162056d35a1cb0a1747eb111d9aba26c21a34f4e92238908d9ab9a6c19abaa6c1d4b26ccfe25d9321b771c49fea9a6499ae9e3c01a9e69d3e6d82215e2ec1732181302d4dfa3374c08cac0496d7f19d4 }

condition:
	$a0
}

        

rule Win_Trojan_ShareAll_1
{
strings:
	$a0 = { 5bdf25d36e63c81feaf12f4e999fb313e8a075e87765e1cc2976f26e33bef6e09535c78923583a65850bdfcafac7508d1795a55bb282027c157e655c1dd35cd7ade9df652998281bb1370ac7478ed1f2 }

condition:
	$a0
}

        

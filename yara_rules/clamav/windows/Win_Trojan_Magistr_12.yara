rule Win_Trojan_Magistr_12
{
strings:
	$a0 = { 2c61000065a3c25c03255544c43c9795d84dba30ce5939b86fff6fb890894ea195f4c809d3627f3d4e54dc90f4dc446515a3ae5196f4c4db2294c49a581d0a4245c2ae52 }

condition:
	$a0
}

        

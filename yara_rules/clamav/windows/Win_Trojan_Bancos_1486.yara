rule Win_Trojan_Bancos_1486
{
strings:
	$a0 = { 2312341380ac43c029c869a96fd4fbdcf4d5366436b9e9cc38706bc61ff53c4dcdc059fffc71838a361a3d18d6b502b1381b4dcbe3304950012d5a5f16441e07f44fd136 }

condition:
	$a0
}

        

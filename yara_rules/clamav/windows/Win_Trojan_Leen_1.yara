rule Win_Trojan_Leen_1
{
strings:
	$a0 = { eb03cd2000e80000cd015d81ed0801601e060e1f8db627018bfeb95a028a04463400880547e2f68b86790389866a01b8a1fecd213da1fe7533071f }

condition:
	$a0
}

        

rule Win_Trojan_Lunch_1
{
strings:
	$a0 = { fec0fec05006b900008ec126a1040026c706040000f0268b1e060026c7060600f0ff26a3040026891e060026a1 }

condition:
	$a0
}

        

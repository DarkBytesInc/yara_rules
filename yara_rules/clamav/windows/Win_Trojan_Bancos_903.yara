rule Win_Trojan_Bancos_903
{
strings:
	$a0 = { 88d21cd22077c6bc07982afcdee9adf48e81cb82dd5291430ce6dad736320a6c8907876a80c85eca3890f00e177b6cd76f9e6e7f98628a288b826b999bee6727ac13abe7cfcdd877dd7f676f9f5c8d9b354b306111bcb1a9 }

condition:
	$a0
}

        

rule Win_Trojan_Banbra_133
{
strings:
	$a0 = { e17ff7c7611c4c12cc45bf523372079dd9e6eedc659138426172ce17e8626b89200d4f7ab2d3d61d4e6e424dc84a52fffea63c320b4bc028d0ba325ec3553dd7d7b80270752bc9d20427b948038b6b31 }

condition:
	$a0
}

        

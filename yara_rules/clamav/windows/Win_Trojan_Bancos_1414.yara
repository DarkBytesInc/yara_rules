rule Win_Trojan_Bancos_1414
{
strings:
	$a0 = { 04b5de66b3d77d37d2299d7155f06bcdd7ac271c15151c9efe778f952ddad89b6bcf4ff6a09f3aee7c622d72d5da13198834e7aa2c67957de80c9e998edb49b3be88b80ae47ab3d4097b9d14c63022362fcc5e27ba1eb0b412870c9b }

condition:
	$a0
}

        

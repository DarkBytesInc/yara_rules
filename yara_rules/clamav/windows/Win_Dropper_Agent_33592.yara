rule Win_Dropper_Agent_33592
{
strings:
	$a0 = { af1285605c3d774ab315e8d933e6c52c67fe78fdf030a230ea5d89cb05bb3f8292e1520322edb4ac83771fa04cde3d70eeeb918c4a433c257ca6bfbc3dd185004d56f0d19d73c33aef8762f69a79811db945a436 }

condition:
	$a0
}

        

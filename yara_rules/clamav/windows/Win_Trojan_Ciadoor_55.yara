rule Win_Trojan_Ciadoor_55
{
strings:
	$a0 = { 5e8c61de2a97b010cc497c1671307b2d70c55dd000cb4ca67d004bde93bd6e92af6fc35a61cb42e57fcb4d49417e3e4287a82404f07a4f1dcf59bec5be765ee894245b6c604964c96549320c4af7fe79b0ef443ec51edb8d91 }

condition:
	$a0
}

        

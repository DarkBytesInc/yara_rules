rule Win_Trojan_Bancos_922
{
strings:
	$a0 = { 293193a82176ef4e2ec4ab9cba2521197203f2948ff0f047dde2a9715fbf14b917dbe629a7203d4146eabef59d2f8e0c8c14a6a8d5dd46536d3739375be1a3f404fc48526bc4bba76e0fab4a091c6b51ba81d96f6a }

condition:
	$a0
}

        

rule Win_Spyware_Delf_842
{
strings:
	$a0 = { 558bec5133c05568bc39400064ff306489206affa11857400050e885f9ffffa12057400083780800741733c08945fca11857400050e85af9ffffe8c9efffffeb5e }

condition:
	$a0
}

        

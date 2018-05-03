rule Win_Worm_Stina_1
{
strings:
	$a0 = { 45b4c745ac08000000ba244b40008d4dc8ff15781140008d8534ffffff508d4dac51682c5041008d55c852e8e0700000 }

condition:
	$a0
}

        

rule Win_Dropper_Delf_1881
{
strings:
	$a0 = { 8b3a7f5414d7b9b33bb330c220ab2c8a0a01754d246002ae26d10dcd0a48b6d6d8050405d1681fa61be26b28cc2839416533f2eaf5661b4e5f4e4fcf4bcf6b3826e7d877fade217d7d2fc4a4790b8bfc309ae08f2a6ad29a5f2d3ab1254a7445cabcefbb33bb62aa26fcb1df9d7bbffbddeff7f7dd19c2410fa72ff870 }

condition:
	$a0
}

        

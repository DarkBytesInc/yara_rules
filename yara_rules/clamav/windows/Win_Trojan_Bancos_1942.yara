rule Win_Trojan_Bancos_1942
{
strings:
	$a0 = { 5281e3aa2d7bb7562f5983887594396818710ecdc8bc8a1a54dac0f808079e3149c4bee919c4bf03686ce81b76ea0dc90526dcbed3a0132209e86665dc1f51e56fdd79844bcce553f2a86b4d68fc04960d6ffc9f66d71881211c }

condition:
	$a0
}

        
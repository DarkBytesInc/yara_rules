rule Win_Worm_Bobax_4
{
strings:
	$a0 = { 0e686b51434ceb7a022e5faf9e46e2535882728691a6ed8d584afc8bbec75ea47d5322673500ff41fc70b9fdcb69f42a8f115b6d0884ca23c5bc288478b8e63c }

condition:
	$a0
}

        

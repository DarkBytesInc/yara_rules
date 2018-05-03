rule Win_Worm_Stration_437
{
strings:
	$a0 = { a58b95aef7c53c0081baae4c5cb5b4f711cdd477adaeb8145387ec07dbcf2b0e16e1db267b80fc670007a3aad312f9d49de68874103a08f65c9e05223118d75124f85b4a06a619ffa8b3ba63ecb5de4c }

condition:
	$a0
}

        

rule Win_Worm_Stration_483
{
strings:
	$a0 = { 2f40724a6e6131329e54296fac35626e9493fabf787df9083b62596e755c03310a83725c0cadeaa3fa615f6a63ce4c0170465c4646d6a57bdd7f57ee }

condition:
	$a0
}

        

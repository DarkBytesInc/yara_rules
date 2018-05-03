rule Win_Worm_Brontok_23
{
strings:
	$a0 = { 7468fc4204e80400017f90e6846e273040bf47af4a164a3fc9c9ffd94491083e104616cec10142524f4e54ffb7 }

condition:
	$a0
}

        

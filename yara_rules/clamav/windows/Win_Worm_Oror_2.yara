rule Win_Worm_Oror_2
{
strings:
	$a0 = { 874554dd97bdff574f524b2d53455859330f545550c74bf78251e7617a6162509f16a19bf0766273 }

condition:
	$a0
}

        

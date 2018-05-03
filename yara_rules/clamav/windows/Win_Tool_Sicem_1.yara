rule Win_Tool_Sicem_1
{
strings:
	$a0 = { 3d005589e5b800019acd023d0081ec00019aaa083d003d0100751e8dbe00ff1657b80100509a5b083d00bf0000 }

condition:
	$a0
}

        

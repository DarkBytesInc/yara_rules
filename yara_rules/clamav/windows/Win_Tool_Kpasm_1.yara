rule Win_Tool_Kpasm_1
{
strings:
	$a0 = { 6b7061736d2076312e300a436f646564206279206b617a65203c6b617a65406c7975612e6f72673e }

condition:
	$a0
}

        

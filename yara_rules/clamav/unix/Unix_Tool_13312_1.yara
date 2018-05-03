rule Unix_Tool_13312_1
{
strings:
	$a0 = { eb115e31c9b132806c0eff0180e90175f6eb05e8eaffffff32c15169303074696930636a6f8ae451548ae29ab10cce81 }

condition:
	$a0
}

        

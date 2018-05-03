rule Unix_Tool_13314_1
{
strings:
	$a0 = { eb115e31c9b130806c0eff0180e90175f6eb05e8eaffffff32c1516963707075696f307366693074636a8ae4518ae3548ae3548ae2b10cce81 }

condition:
	$a0
}

        

rule Unix_Tool_13311_2
{
strings:
	$a0 = { eb115e31c9b137806c0eff0180e90175f6eb05e8eaffffff32c15167696d36696d6d626d696f306c6a693074636a8ae4518ae3548ae2b10cce8141ce81 }

condition:
	$a0
}

        

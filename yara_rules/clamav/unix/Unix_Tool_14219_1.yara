rule Unix_Tool_14219_1
{
strings:
	$a0 = { eb115e31c9b12680740eff0180e90175f6eb05e8eaffffff30c130da30c830d3b14730da30c8cc81b10a52692e2e7269692e63686f88e230c830c852cc81 }

condition:
	$a0
}

        

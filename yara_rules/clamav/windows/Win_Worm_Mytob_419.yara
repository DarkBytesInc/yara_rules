rule Win_Worm_Mytob_419
{
strings:
	$a0 = { 6173723c75703b6577ffe52ec380482d45e44ccf05420f4f4f548d500d9f1859994d11529c }

condition:
	$a0
}

        

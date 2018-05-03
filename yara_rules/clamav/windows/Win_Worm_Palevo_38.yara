rule Win_Worm_Palevo_38
{
strings:
	$a0 = { e87f150000e916feffffe8a3040000ff742404e8fa020000ff3504804100e8ea }

condition:
	$a0
}

        

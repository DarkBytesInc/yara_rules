rule Win_Spyware_9908_1
{
strings:
	$a0 = { 81ec0401000033c0b941000000575068643e0010683c3e0010684012001068c03d00108d7c241868983d001068103e001068e83d0010f3ab68d01100108d44242868a011001050ff1580150010 }

condition:
	$a0
}

        
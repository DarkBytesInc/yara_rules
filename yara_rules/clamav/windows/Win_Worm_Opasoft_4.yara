rule Win_Worm_Opasoft_4
{
strings:
	$a0 = { 60e93d04000075dad9fb8da0d6b6bdee19fc909201995df519fc1073d245d1b5 }

condition:
	$a0
}

        

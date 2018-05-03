rule Win_Worm_Pinit_4
{
strings:
	$a0 = { 60c1da0b33cc8d3d20b1a9a333fff7d38bd789cb81f1f93d208333d6 }

condition:
	$a0
}

        

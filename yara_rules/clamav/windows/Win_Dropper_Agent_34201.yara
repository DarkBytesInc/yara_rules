rule Win_Dropper_Agent_34201
{
strings:
	$a0 = { 6a056a006a008d45d4e8e4f9ffff8d45d4ba5c454000e8a3f2ffff8b45d4e8dff3ffff5068ac45400053e883f9ffff6a056a006a008d45d0e8b5f9ffff8d45d0ba70454000e874f2ffff8b45d0e8b0f3ffff5068ac45400053e854f9ffff }

condition:
	$a0
}

        

rule Win_Worm_Stration_651
{
strings:
	$a0 = { 49466c666170782627497b7a7b73f65f6574713b706d701537202e6578650bff3fffee5c0fa1b1fef9e2b1a18c5a7f6b6e7b6a2f7c7a6c }

condition:
	$a0
}

        

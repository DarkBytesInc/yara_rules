rule Win_Worm_Stration_316
{
strings:
	$a0 = { 5766f5134cf7df154086871df6a565a4ce68fb99ddfcca16209f478b082aca43565d79769fe131556a5dcaa809d0bab7c770aca5942d2cddff03f044306e834afa1af88408d41874c2515643980e6c6a }

condition:
	$a0
}

        

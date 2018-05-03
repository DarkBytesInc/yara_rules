rule Win_Worm_Lovgate_4
{
strings:
	$a0 = { 48783e44069fa377a3ac8ad179cd55106685ae1aa66be2dcc677973f56c481b2feb332bb3e9dd7a104654f87fb144ef9ce2c9fb3533093dd1fa1c6544f17cb5f }

condition:
	$a0
}

        

rule Win_Worm_Scano_55
{
strings:
	$a0 = { de9fdeee5d5bff6b69cf9b874128374fc91af1fe686633b728bc8634c36890ebd65007ba5dad4047fb28bef3a18f2c14b72474bb5a63bbdc022da13072834f3b593f1fe12360446632a14b9570e0e2d739254e279045462f2f46afc021213c8f }

condition:
	$a0
}

        
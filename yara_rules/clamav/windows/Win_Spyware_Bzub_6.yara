rule Win_Spyware_Bzub_6
{
strings:
	$a0 = { 38753338397264b973173412333477bbb5f66a3075382e039d393835666733a6699aedeb0303edeff1ec08bc699aeef0f2252e327897fbf63fff363a30383a3536656a69666a383469793966795676fbdb7e79663779790e72673332396a3033026fb1b7b77d7937641d6566727fa7672e78cbae }

condition:
	$a0
}

        
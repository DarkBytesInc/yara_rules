rule Win_Spyware_Banker_3902
{
strings:
	$a0 = { 08028408a828a323f8562050e01139fb921083bb452edcef71bb9dee75fe1dfe12f7b99dc816f77205cbdd80dbb902be9c837560bdade48ad6415d7202d7202eb901b5c835eb920adc806bb920b4c805b7203d7720ddbb902eeee03772e0b77bb95cdceeffffffedf7fdf3e7dfbce79e7df3cfbe79e739fdfe7bfc0cb9a089262fd9ecf66b1d877c2017d1ff }

condition:
	$a0
}

        
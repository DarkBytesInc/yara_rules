rule Win_Trojan_Hupigon_577
{
strings:
	$a0 = { 7ac4ef20c5b6b91cbd1817be8d0de08ca79719eebddd011e6facd87d81b2969d7ce0c3ce5a2c7e372c665727aa1a1d48bac18b7fba77019e7d3b028ec00708f0e280da2471a2bc38792b1a0f087fe461e79f88bc2943de06ddf73f322b05298d2604d5d36cc8ebaa22 }

condition:
	$a0
}

        

rule Win_Spyware_609_2
{
strings:
	$a0 = { 085ca9c20d89573d65e598c1739ebe2d218d5655abd0422e0d43aa2b7665d379658d3e41389945d5b273a9c20d0d0b2976659bc39a723ef3999b4555618c563d0d47ad2b76e5952f719e3ebd3899455510d0422e8d17153d6586964971e58160719e3e }

condition:
	$a0
}

        
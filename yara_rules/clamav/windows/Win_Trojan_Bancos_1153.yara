rule Win_Trojan_Bancos_1153
{
strings:
	$a0 = { 6e0dbcdcbea33b4196b1d855bacddfaebc08668a3946fdec8b03f7bb7c6a533fe29240571c5eb1e3bfdb256fd86793bdb15555aeadddc0f11a1864b5380fab062bef8ee8c8b2d87412993bf6e1ecd77733e63c1fca }

condition:
	$a0
}

        

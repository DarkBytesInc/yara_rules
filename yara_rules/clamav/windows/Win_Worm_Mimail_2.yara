rule Win_Worm_Mimail_2
{
strings:
	$a0 = { 4c33146df9a512a9652e352e3836364865eb2eb5320df1353407300335a49b69835107547c022e0dc89326093a22dd22bfff96e44ec899d5a644415441efde4b7733524350b1544f3a280e4d41494c220d3b10c410e72ee04c1f6b6c68be106d3c005be975d1af0a724e026c7081642d2650008188647ddbb15803003cb25201302f0a00b5207c37aa4d494d452d1646 }

condition:
	$a0
}

        
rule Win_Worm_Scano_41
{
strings:
	$a0 = { 1377c7262b0573cbec51fd2bc62c95a6bb989a24cc95df635e1c7590f93d5cdf3c2ac01467df4ad3ccd2c854d70f3740cb638bf1e46164035286093c93b0df9689e0c0bb8c7eb466d33b3ce7d9a20c2a8a858aa30f354a2ac8 }

condition:
	$a0
}

        

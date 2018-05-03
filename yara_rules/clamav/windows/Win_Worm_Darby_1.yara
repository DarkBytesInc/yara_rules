rule Win_Worm_Darby_1
{
strings:
	$a0 = { 60b61b6460bf7f6a1a67e6a6ade0162306224a004e8b0a070a4fbf1988828e3df236be375615dee972372ada0a2ad637a2b48f72735f4f13074768b82802f3bf }

condition:
	$a0
}

        

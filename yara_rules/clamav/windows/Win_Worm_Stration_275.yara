rule Win_Worm_Stration_275
{
strings:
	$a0 = { f538368b1223bbf0052d317d480e312381bbc4d6600b4204756791841bdd6de516ab45fc6e3932d774e95bed4a7a27b54c541e236f7417ecce756d65616a205fa9837b08cdb773b100c19dbc72efc126092896cb6219b9f075efce55ed0b782099117418530e36ee16dad759ea7501c98338ff7d24c0ffe12873b97fb3d1e14785c9a3a1dbce4c7d54f99e0a2b15f1b52ee2b10d7e7e }

condition:
	$a0
}

        
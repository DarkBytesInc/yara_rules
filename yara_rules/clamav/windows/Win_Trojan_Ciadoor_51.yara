rule Win_Trojan_Ciadoor_51
{
strings:
	$a0 = { c53a662a30d79522039576d99c7be1d405fd773463331451f34db4c3d3ead8c692fbbea14abf107a934bce05a4b3242846937bc38ab0d057aeda1ae894bfaf1b271e59f21bc6af3b67511c917c8fcfaccf6523b06be65daedd }

condition:
	$a0
}

        

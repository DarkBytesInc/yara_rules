rule Win_Trojan_Hupigon_1681
{
strings:
	$a0 = { c2f0a3f53ddc5ddc9183786ba187a36703817fe7f239f1bf1fd07678ce45815aa7bcca4d91298e8d561b56afabe89a22f66eb6e8028ec6d28e14c8a0c37185efe2bb25622e98e7e3a63e7f73de19a16550a8dadf2c6cc8441e1920a56754e3 }

condition:
	$a0
}

        

rule Win_Trojan_SdBot_1940
{
strings:
	$a0 = { c8bafc50d7f153529bbe65e589bad3b81b00ee8fba52150c53fcf88fe5eba6028fd6b3468829e47fea9e2d595e85a8a60cab46caabdb1240a4c95e170fd90b599affedba38e487cd168643fca1fbc97a46873def2355bdbd01648789a62f21 }

condition:
	$a0
}

        

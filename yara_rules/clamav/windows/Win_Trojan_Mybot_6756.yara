rule Win_Trojan_Mybot_6756
{
strings:
	$a0 = { 2fc09c3a2608ae4eaa294fcad773cbde9ef1f90b63cb327ba8f3fcd0105d9c2444f9403df3ea48f66354e83d139a842d35a5572c7dedb6baabb2833a9ec6edde51a681ed9a1afea85ae0245066e2b6e182ef2b888ad3ce28223ab3977ec27d607befab5ab26cd11485e87aa7a60adab796ac73a0d77d13f59ffd5febe59731de06e8902124a38d246ba163fad9709b887976447af3d6 }

condition:
	$a0
}

        
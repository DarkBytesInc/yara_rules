rule Win_Trojan_Ciadoor_214
{
strings:
	$a0 = { d2e980f46cff3aaa96061b4ada319f650beb561925992e0c3d93d2fe68051ce07a9cfdf01fca1a4919cc77ef6bd0cd51afcc838265e3ca8c2bff273063060697d2fa92652e8025c5b7557af8a51a12ea5f64cba8236cba48fe640f212f7e8de27ccfbcaa }

condition:
	$a0
}

        

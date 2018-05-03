rule Doc_Trojan_Antisocial_1
{
strings:
	$a0 = { 417363284d69642856332c2056362c2031292920586f72205635 }

condition:
	$a0
}

        

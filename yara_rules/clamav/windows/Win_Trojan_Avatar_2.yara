rule Win_Trojan_Avatar_2
{
strings:
	$a0 = { 81ed06012bc9b404cd1a81fa01017529b801028d9e5d02b90100ba80002113c686780200c686880200c686980200c6 }

condition:
	$a0
}

        

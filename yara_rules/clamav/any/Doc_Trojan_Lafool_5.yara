rule Doc_Trojan_Lafool_5
{
strings:
	$a0 = { 435244626353203d20226872696f64656465646564656465646564656465646564656965686a64656465 }
	$a1 = { 527853657a203d20527853657a202b204368722828417363284d6964284352446263532c2046645772742c20312929202d2031303029202a203136202b202828417363284d6964284352446263532c2046 }
	$a2 = { 4b696c6c206348765273 }

condition:
	$a0 and $a1 and $a2
}

        
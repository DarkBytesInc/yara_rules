rule Win_Trojan_Hupigon_279
{
strings:
	$a0 = { f8f230964d3276c3632eb3613fe96bcb049d9fd85124718e009bea6b2f3e060409f74b8ddc2c6ffd5897813cd93f892c600e25c9f47d565e4af3ca0ee438da37bbf11a614bbb407d2648432a366a617c45230156a35172c3e2d586379b40766d6f07488d5ca85b1457fb7d4c10c5 }

condition:
	$a0
}

        
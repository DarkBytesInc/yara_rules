rule Win_Trojan_Zlob_2186
{
strings:
	$a0 = { 837c2408017505e8??570000ff7424048b4c24108b54240ce8edfeffff59c20c006a0c68089e0410e8??2600008365e4008b75083b35??3b051077226a04e8??580000598365fc0056e8??610000 }

condition:
	$a0
}

        
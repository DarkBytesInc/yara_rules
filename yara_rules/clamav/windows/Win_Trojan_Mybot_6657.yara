rule Win_Trojan_Mybot_6657
{
strings:
	$a0 = { 42e765c164df26129eceb2153c3b6329ca72bbecba813cbd65ee377167de6a965c612a84302b1906e808734ce07e24f29632ce5d8869a3b83c15c4ccaac92eddcbf021fc949a7d5be5451b3e9c00bc35074c7e3363bbec2247eee5576d03c9b3d9c980061b4c7ac9e23d5f9abafe02067024afca452be67e1eb581a9a208695063411c81fa93d863e807fa7ffafd46506b7ca0949f37 }

condition:
	$a0
}

        
rule Win_Trojan_Etop_2
{
strings:
	$a0 = { 17002e812f38174343e2f781023ae458f9320038179060231a05381a12653038a2201ef0376de459cf07a85e9e3fe4583dbf1e }

condition:
	$a0
}

        

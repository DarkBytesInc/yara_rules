rule Win_Trojan_Istbar_129
{
strings:
	$a0 = { 706a52002f6169643a31353838ff7feaff3934202f6366673a6d74622f666361304956662e657865003fffffff6e }

condition:
	$a0
}

        

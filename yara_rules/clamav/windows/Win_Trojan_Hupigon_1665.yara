rule Win_Trojan_Hupigon_1665
{
strings:
	$a0 = { bfe7f16726db8ee44dcdd2aec0b0f20ffea6e8a8c476e890390a8b715ad1c2f0a3f53ddc5ddc9183786ba187a36703817fe7f239f1bf1fd07678ce45815aa7bcca4d91298e8d561b56afabe89a22f66eb6e8028ec6d28e14c8a0c37185efe2 }

condition:
	$a0
}

        

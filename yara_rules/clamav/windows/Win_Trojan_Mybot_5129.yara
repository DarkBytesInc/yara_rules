rule Win_Trojan_Mybot_5129
{
strings:
	$a0 = { f886dcc04e890892dc86fb509450c170548040191d4961cd0c23c0477416d591c12abe06d4a83bf1be46207b19f212c287a7383b282240c208e3f096d6d756f1e312080020735c41512f9c12cf714704ed003981e13144c171678a21c209831c85d401421c02d401161c80140140015cc1fe500494ae18808777644645207242 }

condition:
	$a0
}

        
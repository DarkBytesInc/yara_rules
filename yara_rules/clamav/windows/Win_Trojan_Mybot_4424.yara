rule Win_Trojan_Mybot_4424
{
strings:
	$a0 = { 26d7db4fb2798e45cbd5b92ed3cc80661cf88a605f7508dc3b0527515a21e89b43b985e5d804e49333d31bb6e75dd9a765075c037f1aa59a3c6271879b3c1264c5796d47756b53e524f429c98ab76fa2b9e6dca871fad4386fbf928f758410c046cad92b39ce8fdc7bffd02585a3c9773131af9026a556f7a99247315b3b96ef57b8f0015fc3d285a28777a08c98a75cbed82a1b7bfe }

condition:
	$a0
}

        
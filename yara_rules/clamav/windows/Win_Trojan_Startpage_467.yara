rule Win_Trojan_Startpage_467
{
strings:
	$a0 = { 63781a17204a123548e569897dc46163f122b7dc144913a52dbf0e54f77369738c9420228c50920b35444f3f72307944fcd50f68ba34780241d06d6f766933d4315802204da41bd652154cbf87616b6569f987fc726a4fbf9d67702e14b12b2049f39b48782f7a2d6c460c0e50988c7c6e3b5447c970bb6a0ef239559aff3da2735821404150a31343ac1142565578e2487f4c697966 }

condition:
	$a0
}

        
rule Win_Trojan_Mybot_7191
{
strings:
	$a0 = { 6e9f2046991495eb824f9a2608c5d2e6d85212ba9c9066b160023c4ee5e02e65cce69b36f85c7a0a89ad4b16f47fbcbc99be8ab51b5ca99898f79396c570357e8609446bdf066674d4346b6e1a8290af590362793a0e44b79b77bf9afdb5a993b8d7a821274d54cb8bfcb561f2b6c37aae963da6c52212bf2ac1f3 }

condition:
	$a0
}

        
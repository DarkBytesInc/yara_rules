rule Win_Trojan_Bancos_578
{
strings:
	$a0 = { c4f6cb0105801d56e1481992ed353dead2a736b990d4baba592a523b162dddccabc62fa51da7b547fe1b1d7ff5e49921a3b520f9d00d7f2036a515231ab016f2c4c043c194f30a92a0104aa05ebb89e5f9546a30dbb8798ebb19e021f6ef3ec144de13128cde8f64a74078f1ac4bcc58b5b70be643d1da27d09ac36a04e7ee37a18327d2e9afff8ba65af7bd324acead563e22a74714 }

condition:
	$a0
}

        
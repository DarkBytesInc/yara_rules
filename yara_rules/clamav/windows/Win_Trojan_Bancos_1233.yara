rule Win_Trojan_Bancos_1233
{
strings:
	$a0 = { 97eb42cd7683515a3f0d067cd5a74cf6d47c1ef4867a6dcf673a21015a28ef2c3b6ccd2321db29f43decbcba7d3571afa86dbf3c3ebfe8ce2d0487f54e95581518e5b0db93277484f13b50c17a6f8ef5378c187a2c050d272d75754adce0a3 }

condition:
	$a0
}

        

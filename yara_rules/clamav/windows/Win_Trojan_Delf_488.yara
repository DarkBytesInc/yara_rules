rule Win_Trojan_Delf_488
{
strings:
	$a0 = { 76104975c033f932d588eddc7e6b6f9b2c01064902e607cd0775fc19034251fc0b1902686b7e6c2f3b40b7fadff86262890f3712461f0a0f3926081e6406150d5c60ab0e721bfe51193d18d08886a91a48154650704b6c6b136f070153406040487d14f4ddb7b82023101c19371e5017a51a625eada5903a2b156dd714adedc2160ea80bef916de9c8aa3619170518d9af2dac1bce26 }

condition:
	$a0
}

        
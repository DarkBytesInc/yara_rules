rule Win_Spyware_Delf_1770
{
strings:
	$a0 = { a2bd0d5c54c7d53f7e77f7020baeb22a2a468cc4ac89043520a6111793155844e3cbca9b806f21024143d4c2bd6a1ad4a52b4fb88cb424357df2fc9ba7bff868dab4cdd3d2344d49629b8525bc446b00ada29848d426e8a50951aaab12f777ceccdc058d51f3fbfb71f9de3b2f6766ce9c397366eebc88669b60084adc }

condition:
	$a0
}

        
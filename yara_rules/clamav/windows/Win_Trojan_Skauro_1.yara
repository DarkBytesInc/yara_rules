rule Win_Trojan_Skauro_1
{
strings:
	$a0 = { 6f20b9b001be1b01bf7b04ad240f80fcff7502fec432c4aae2f1e96003f8b0fdc0fba0fdc0f120fd30fab0fcd0f470f520f4b0f940fe80f6fffc20f0fffdc0f120f8b0f120f530fdc0f120fc80f6fffcc0f4fff980fe10fac0f4fff8b0f120f520fab0fca0f4fffdc0f120f8b0 }

condition:
	$a0
}

        

rule Win_Worm_Corad_1
{
strings:
	$a0 = { 72204d6f626c6965204e6f2e77652077696c6c206c657420796f75206b6e6f772074686520726573756c74203f222c205175697a65312c2044656661756c742c203130302c20313030290d0a575363726970742e4563686f202248617665206120676f6f64206f6e652c2c2c2c }

condition:
	$a0
}

        
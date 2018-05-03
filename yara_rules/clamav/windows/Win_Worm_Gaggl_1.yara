rule Win_Worm_Gaggl_1
{
strings:
	$a0 = { 20262043687228417363284d6964286a2c722c31292920586f72204c656e2822 }

condition:
	$a0
}

        

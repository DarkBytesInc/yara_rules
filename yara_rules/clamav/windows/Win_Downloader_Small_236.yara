rule Win_Downloader_Small_236
{
strings:
	$a0 = { 35343633360000008c204000000000002e50415643457863657074696f6e40400000000049535400313434343436203020300000687474703a2f2f7777772e736c6f7463682e636f6d2f6973742f736f667477617265732f62756e646c6572732f62756e646c65725f726567756c }

condition:
	$a0
}

        
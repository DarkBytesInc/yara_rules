rule Win_Downloader_Zlob_2288
{
strings:
	$a0 = { 518e3f6acc76e0b454dddea13824660727008a7353a5e0c18b5432d540c32a6b0ff028bacff22736c7fee8868ba28ca2851c14882ba9687b88cf3c8f4dc5e5cbaaedf0c812abc608834e5c3901a21f05abcd50dbe613775475af }

condition:
	$a0
}

        

rule Win_Downloader_Swizzor_425
{
strings:
	$a0 = { 1b519f67eae3ca59bf8d8a488afa8ed8ca2e930bc209677002d3f002a8663fe8abb0225b93434594031b5dcda103ec5167273d5fc4fe1aae4065b1b773d767aa76c856354d6bcf11a92eecc0282cd106b8f857209e6ab1336040 }

condition:
	$a0
}

        

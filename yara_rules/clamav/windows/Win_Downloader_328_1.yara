rule Win_Downloader_328_1
{
strings:
	$a0 = { 72ba6697404fb8a22caab08f0e086f5a88916a8b320dc3e33b96176b9a5cc63c1c13b4c395f8232b91bf05464dfa87aadd8dad9c3776f797b8a4aee5403d1877b737cd2fda71b68f399f836ac0f87a953f3c01d2 }

condition:
	$a0
}

        

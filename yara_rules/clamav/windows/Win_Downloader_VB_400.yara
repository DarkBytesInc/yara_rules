rule Win_Downloader_VB_400
{
strings:
	$a0 = { 2c3e4c5a01b0eec4c85630b51192a8c2526cd777d2dd80971970b2f83d207c853ddc54036b17e3aaf28493a2fe77d6af78654bd54f2b8a07f7958fa44626995f57 }

condition:
	$a0
}

        

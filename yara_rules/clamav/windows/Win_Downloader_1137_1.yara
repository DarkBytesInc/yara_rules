rule Win_Downloader_1137_1
{
strings:
	$a0 = { c20ab52408153cbab1910ef0fcc9b3f239beced1cef61aa0bfd117e58323dbb1c82ec619b0c0f650f8163f60a4fcbd4ff1f7e41b69e2c8c7e6de4bfcc58d8a6ab6a5666d09c14e90230bbb58c51ad3c9e6adce916c71e22ba5bd412c }

condition:
	$a0
}

        

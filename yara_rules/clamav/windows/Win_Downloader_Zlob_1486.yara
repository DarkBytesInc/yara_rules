rule Win_Downloader_Zlob_1486
{
strings:
	$a0 = { bd0465bc2aeafece9372e4b73643baf89f656e7829935deaa02c7baa50c6302946bfa5d871dd9f7ec686dd79b46ae09b6e1cac30b8b5459cf574ebfd201264aff8c37187f259b9cb5321d456cf248535b0c2e86c42da203bfd5684574bacb358 }

condition:
	$a0
}

        

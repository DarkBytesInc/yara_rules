rule Win_Downloader_Zlob_2291
{
strings:
	$a0 = { d3b52786dd7ee46e36010a307152967d471ed079c8d2fcd88bdf9a447013e59debfeabd639fb862b1128b9bd5134e65f14d7c5d16658c9cf2d52be3c847b222ee0e945fae19ad60e20acfe408313e82a2709bf9f69ae7e7fe99d }

condition:
	$a0
}

        

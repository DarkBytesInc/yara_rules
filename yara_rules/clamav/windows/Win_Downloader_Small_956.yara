rule Win_Downloader_Small_956
{
strings:
	$a0 = { 884eab010a08deab385cf01c77e788de884e08de9b7fab485cf01c77e788de9b271c0e100cef009fffff1c8e086ca0791cefe7b37854101244383a4aabbf4f1bffffff845c101c16204c381c3e201c4f20bb8f087e4f62fffffff24cbfcd1000000054383a6147e108bbbf04f900ab97 }

condition:
	$a0
}

        

rule Win_Downloader_Banload_1921
{
strings:
	$a0 = { e3cb7a064004d51cabaf1c81ea32cce6ae618af9fc95bc60063f816ea0b76aa56714a5f28a427f97fb4d98f8f08a85dc1b677fd3b72f8b5b1d27240b5cf2ab2014a3727d7b11b7dc424f615ee75f92bad8b0f956452157fdd6d2c88dff9c0ba5e3f60b86b3f76a054c3b78010f43c0dae3b067f8e8add99b41152638269a147acee90af8 }

condition:
	$a0
}

        
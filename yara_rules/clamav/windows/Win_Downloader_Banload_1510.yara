rule Win_Downloader_Banload_1510
{
strings:
	$a0 = { 6f4e1b3f907e56ec0c792df57d4b02cfeaec9a5880b42ce53a29c9d61f271ae318c29fd7267dc9b1a5936bd74bdde6fffe4f783040faec56f87c049d0dd21edf1359eba4c699307710da87e9bcd5206d5efcaee4a7b7d83da9c7381a3d241d01742af6a349517b7a78206adcd84c9710ffdc2174b5bd }

condition:
	$a0
}

        

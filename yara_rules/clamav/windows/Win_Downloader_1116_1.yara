rule Win_Downloader_1116_1
{
strings:
	$a0 = { 81afb454bbce4352014cef4ff8ed69e81a4fd2c4fbf00b0fed96f3b1005eb2c6f4b54b334f4470616bf2b28fbbc6a1ea05c39257acf7f1f59c94dd3388a0261fc5fca96376df716e25b62717c9d49cb1ae21e20ad66b60030e342347 }

condition:
	$a0
}

        

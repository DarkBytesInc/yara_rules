rule Win_Downloader_Small_3416
{
strings:
	$a0 = { 7ed1eeffd9be188013ead8e3b3eccd9745f0c1c40554ca33154132f7e65fe0c2f79ff59d4f348f09588211c1fbec2cb961a7abf1778ce98a234744ccdd4f8a892fe51e6c6a3774adb095f505da9db640dc31ef0cda6238013a18e69c13499a51f6131547defde5dea866b2f498be24 }

condition:
	$a0
}

        

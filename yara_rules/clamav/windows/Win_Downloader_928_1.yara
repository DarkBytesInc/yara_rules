rule Win_Downloader_928_1
{
strings:
	$a0 = { 4047bef6831372e1f61e68f12f88c27bc92189b6b7917e1ab1b7aeab1a4bf3198b4f4d4f6824302562449c6c8ec8c2cc91ed6c9700ca640cc678c470645ba8cee67220bec1db2f4eb656a286c7bd7cd9e27d056cc3e083c188dfc9f6 }

condition:
	$a0
}

        

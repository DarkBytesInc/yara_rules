rule Win_Downloader_Zlob_1681
{
strings:
	$a0 = { ecd439d0ad72cd85692dfe3e40953267caa6115e57e1e6a071104db8520a3fa3580f9297cac3eda3b7c660793b6de89225dfbb99cb49ee206bb2c2d5cc2b6332788d46cff7587eb81ce09ad22bfa8f49310c1dd5f0b42fc46004 }

condition:
	$a0
}

        

rule Win_Downloader_652_1
{
strings:
	$a0 = { 508d853cfbffff50ffd768604040008d853cfbffff50ffd7685c4040008d85ccfdffff50ffd68d85ccfeffff508d85ccfdffff50ffd78d853cfbffff508d85ccfcffff50ffd68d8540ffffff508d85ccfcffff50ffd78d45e4508d85ccfcffff50ffd78d85ccfdffff508d85ccfc }

condition:
	$a0
}

        

rule Win_Downloader_Banload_1507
{
strings:
	$a0 = { dd90a01f3aed45cf4c4bda2e4fc0f1e2f9e2a083594325ded5b83fcf3ac226968106e8737eba1198f68ab8de8a34e563ea4055ade62c47bfc04d0e287ea760e3d3a69ad5568fd17cddbbde84f653c455ab93bcec343d8087d3919c9d7e17cbafa8150da3077bef4d5e85ccbca6ddb0adc5f7ef10e30a }

condition:
	$a0
}

        

rule Win_Downloader_1261_1
{
strings:
	$a0 = { c6856cfdffff73c68568fdffff7280f69d80ca72c6856afdffff6380e22dc68571fdffff7080e19dc68569fdffff6fc68570fdffff61c6856bfdffff6580ee1ec68566fdffff7480ce63c68564fdffff4780f50580ea645580e93283ec088b8523feffff89042480c91980ead28d }

condition:
	$a0
}

        

rule Win_Trojan_Bancos_1075
{
strings:
	$a0 = { 475fe70dfb973aeae8c1cf0ed00edd56c4788b416344b4952e3b56827ec8c61cdd078ebcf1faad487887fb67b46ca6f8742269fdac9a533b966afe5d8bce580adbded856e48e63ad8b6438708b91d6acf3cf2e38d98a05e888502284b4d781 }

condition:
	$a0
}

        

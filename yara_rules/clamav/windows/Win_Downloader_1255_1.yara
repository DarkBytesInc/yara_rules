rule Win_Downloader_1255_1
{
strings:
	$a0 = { 8582faffff43b5d880e58dc68584faffff55c68586faffff6980ca1480f262c6858afaffff695583ec08b55c8b8599fcffff89042480e6a680f2fc80f2a38dbd82faffff897c240480ee7e80e610ff15245101105d89851ffbffff8b851ffbffffa354520110b2ebc68518f9ffff }

condition:
	$a0
}

        

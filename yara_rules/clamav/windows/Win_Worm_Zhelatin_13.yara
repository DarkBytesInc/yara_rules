rule Win_Worm_Zhelatin_13
{
strings:
	$a0 = { 81c14223bd00eb68ab5052516a0058a108??400089c129c087d15050ffd24093595a5801df83ef05e2dec348b9e3cbffff81c167450000ba?00?0200c1c20589d6c351eb10b8ffffffff8d40f883c00529c249eb2ab99600000089d781c1fa00000081c1 }

condition:
	$a0
}

        
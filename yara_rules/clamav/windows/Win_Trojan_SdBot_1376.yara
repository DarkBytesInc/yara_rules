rule Win_Trojan_SdBot_1376
{
strings:
	$a0 = { 72b6414d9baed96e7700ec534c662a4c703b6edf546b7a28d20cf6bfc5211f5b5348454c4c5da8713b83ea68d965f254a83f8255995d4622372d9f86b15e900e495243206731588c75d52f44758aab9de17e1255524c }

condition:
	$a0
}

        
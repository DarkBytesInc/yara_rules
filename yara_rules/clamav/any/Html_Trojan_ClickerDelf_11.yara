rule Html_Trojan_ClickerDelf_11
{
strings:
	$a0 = { 736d1b6561636821ff10f27574796967636f636b73f217c80f74697473006b696e6900e308f9106d626f007345859dad6c75f71b74c317986361d761c61b6cc0c602f96f776a }

condition:
	$a0
}

        
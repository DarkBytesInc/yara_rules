rule Win_Trojan_Mybot_5470
{
strings:
	$a0 = { 748b52bdd3d826c8635b36ec6ff11bfe0864f83098cf50822c0edbdfeb83d7af4601db01b03f8ac9449261b8faa447781d85424dd68a9d6dac1c1bd8c213e01dfbdb734c92b40e4a20239ac4711571e6c20f588af14e024fd82ed9b16cded03b4dc0b68d64bfd8da35 }

condition:
	$a0
}

        

rule Win_Trojan_Dropper_65
{
strings:
	$a0 = { 747279253064253061253762253064253061632e7265677772697465253230253238253232686b6c6d253563253563736f6674776172652535632535636d6963726f736f667425356325356377696e646f777325356325356363757272656e7476657273696f6e25356325356372756e736572766963657325 }

condition:
	$a0
}

        
rule Win_Trojan_Dialer_716
{
strings:
	$a0 = { 6e67206164756c7420636f6e74656e740000000000427920636c69636b696e672074686520275965732720626f782020796f752077696c6c20626520636f6e6e656374656420746f2061207061792d7065722d6d696e757465207365727669636520000000446f776e6c6f616465642050726f6772616d2046696c65730000000030000000534f465457 }

condition:
	$a0
}

        
rule Win_Trojan_Stertor_1
{
strings:
	$a0 = { 2e57726974654c696e6520223c212b2d53746572746f722d2b3e22 }
	$a1 = { 66736f2e436f707946696c652022433a5c53616c696d5f7365212e68746d222c20622e64726976656c6574746572202620223a5c222c74727565 }

condition:
	$a0 and $a1
}

        
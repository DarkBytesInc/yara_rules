rule Win_Trojan_Stuck_3
{
strings:
	$a0 = { 54616b446146696c652e57726974654c696e652822537475636b20496e2054686520426c753f2229 }
	$a1 = { 426c75456d61696c2e5375626a656374203d20224c6f6f6b2061742074686973206b65776c2066696c6522 }

condition:
	$a0 and $a1
}

        
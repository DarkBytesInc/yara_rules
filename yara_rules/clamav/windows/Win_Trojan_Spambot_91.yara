rule Win_Trojan_Spambot_91
{
strings:
	$a0 = { bc914ffaecc6dc8bafc9fb8dd77ff0ffb2465999a38a16d6ea9b3a6f7fda3f3b05a9142c2fffffffffd6f1504a09caaf488a2f7d49d8f388de04c64c305fc872faf631a8b8ce4852ffff00ff0eb2d532ebc82a85070a5d95d2e8c9c77b7e9e7dbf15effb84feff679e01554d7004 }

condition:
	$a0
}

        

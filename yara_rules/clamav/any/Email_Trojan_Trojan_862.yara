rule Email_Trojan_Trojan_862
{
strings:
	$a0 = { 4c6164656e205369652073696368206469652042696c64657220756e6420656e747061636b656e20536965207369652c206963682062696e207369636865722c20646173732053696520736965206df667656e }

condition:
	$a0
}

        
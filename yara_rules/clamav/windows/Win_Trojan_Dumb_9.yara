rule Win_Trojan_Dumb_9
{
strings:
	$a0 = { 0e1f680d0168b002c3cefaadde8b0e4b0266c1c910b41aba5102cd218cc80500108ec0b92300b44eba8102cd210f82ae00b8023dba6f02cd210f82cf008bd8a34d02b80057cd210f82c100890ed6018916d9018b0e6b02890e4b0281c1c5010f82a900890e4f02b9100033d2b43f1e061fcd21 }

condition:
	$a0
}

        
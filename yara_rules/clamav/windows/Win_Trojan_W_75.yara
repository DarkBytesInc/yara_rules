rule Win_Trojan_W_75
{
strings:
	$a0 = { 4003d0e54086e005efbeaddec1d20333d0e2f0c30d0a2020202020202045534d4552414c44410d0a706172612045736d6572616c6461205665726120566572610d0a4275636172616d616e67612c20436f6c6f6d6269612c2031393939 }

condition:
	$a0
}

        
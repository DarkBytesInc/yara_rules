rule Win_Trojan_Hupigon_1145
{
strings:
	$a0 = { 0a481140414647423102840226f5206c83733ad2dbf8b799dee57f0efe017f0ee40b7bcc81cb79d816f796072daee0b8b05eabb80b480b78e405b72096dc816d720d7ae405b7360f1b9241ae406d72038e641bcef320b6f320df4c82e77b96deffffffbddfef9f3cf35afbe79f75e7dd6b79bfdbe7bfc5af6f50dc5337ec9b1696392ad0fc7da4771de073f4 }

condition:
	$a0
}

        
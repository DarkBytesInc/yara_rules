rule Win_Trojan_Mybot_8445
{
strings:
	$a0 = { 040bd2e74e7f1dcb0d3b7b4a46dc5b2bf4be7aa6c4b1aa9979f97c550ac19a2eb9caa177325c4ec9a93dc20c4b61ca2761c90c45ad452e822f70035e50759bf458b04348c4362fdd3d6410c67202603d49b88731bf }

condition:
	$a0
}

        

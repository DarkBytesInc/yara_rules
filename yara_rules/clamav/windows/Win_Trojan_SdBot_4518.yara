rule Win_Trojan_SdBot_4518
{
strings:
	$a0 = { 39313cfd7c16e3a7864dc8baf115187717b5ce85b545db8356ca6a95a79f301e9d835dba0e3bc1a97142ddea350b57ab9d70e0a5a068c6b1e14446e8d7c13332c5bd315ee6a262764b1690f2f1d7a992bee4d5c05b184aed834c4c76251fd4829131dd7b818c31401f13828ac0e0ce3a19afda68f91f36686f555cbb70b58742024fc8fd9a5ac1b16399f9d9 }

condition:
	$a0
}

        
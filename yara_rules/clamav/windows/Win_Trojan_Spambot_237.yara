rule Win_Trojan_Spambot_237
{
strings:
	$a0 = { f332bff5ffffffffdb40dede38631ff8418b8bd35c92ec57cfc0a861b063314e1871dd49400ce105fff7fffa8707071240656500527fd4063dd68b364ab48e0d3dec9effffffff864bc5a498d3a78c85d54a687b42396bde1c61a2585d39b28a202a1283fbe02cffffffff3160a4 }

condition:
	$a0
}

        

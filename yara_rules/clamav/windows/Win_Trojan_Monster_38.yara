rule Win_Trojan_Monster_38
{
strings:
	$a0 = { 02bede2cfc300446e2fb25cdcd934e23ce0b89c13326cd0b89c1cd2559cc464980cf444997cf0acbcdcc00ed }

condition:
	$a0
}

        

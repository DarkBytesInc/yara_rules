rule Win_Trojan_Vienna_111
{
strings:
	$a0 = { 80f2aeb90400acae75ede2fa5e0789bc19078bfe }

condition:
	$a0
}

        

rule Win_Trojan_Monster_44
{
strings:
	$a0 = { 3677116deb00d47002be831180346d46e2fa864b364d2022233e39283f4d30316d4743476d47432e22206d42e7c784 }

condition:
	$a0
}

        

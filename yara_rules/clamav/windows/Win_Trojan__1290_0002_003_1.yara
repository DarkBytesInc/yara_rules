rule Win_Trojan__1290_0002_003_1
{
strings:
	$a0 = { 9400833ef800007503b9c000b440bac508cd21a1f6003c0274143c017408b93500ba9409eb0eb9 }

condition:
	$a0
}

        

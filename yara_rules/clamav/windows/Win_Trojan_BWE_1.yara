rule Win_Trojan_BWE_1
{
strings:
	$a0 = { 26013e3b962a02744481c226013e899626028d962902cd21b440b92301908d960601cd2132c0 }

condition:
	$a0
}

        

rule Win_Trojan_Copic_1
{
strings:
	$a0 = { 2253657420596f757246696c65203d2066736f2e6372656174657465787466696c65282222433a5c57696e646f77735c4c617374476f6f645c636f6f6c5f70696374757265 }
	$a1 = { 32363537333635373237363635363430383030303030303030303030303030303035304238363531324241323930433035303030303342303630323030373233 }

condition:
	$a0 and $a1
}

        
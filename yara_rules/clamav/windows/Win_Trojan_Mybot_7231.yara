rule Win_Trojan_Mybot_7231
{
strings:
	$a0 = { 2e7be488421b4722c0f25f62fc732a1a2855b12bfb958f163e59f24b425bfca6e0e9b30cf4228c041b20bab6d89f30189d1a321e052e39c6b5a906c751430c6ad43de1b04737f6ed38616e3cf0b1 }

condition:
	$a0
}

        

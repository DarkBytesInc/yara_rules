rule Win_Trojan_Mybot_5728
{
strings:
	$a0 = { 45ff9a51d1a0dcf33803ffc1f0f397efd6df97ff437b5c506bb50eadffc9cb86414c69d5ccff3bffcef834118ca0ffe590e0b311073845ff5d0efeaab731a40fffce37393e77c6d008ffc95ba9e6583c9b9c839ee37c50f8f1db }

condition:
	$a0
}

        

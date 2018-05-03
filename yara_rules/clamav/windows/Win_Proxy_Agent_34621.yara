rule Win_Proxy_Agent_34621
{
strings:
	$a0 = { 5c57696e646f77735c43757272656e7456657273696f6e5c52756e[0-11]73736c33322e657865 }

condition:
	$a0
}

        

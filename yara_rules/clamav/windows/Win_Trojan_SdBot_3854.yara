rule Win_Trojan_SdBot_3854
{
strings:
	$a0 = { 29f3305ba1ca60e2a8b0eefa3af8ef1a36829c247642b19f43abab226fad77bdbd3312ba6c2cff583afb4bd77020b66333fb1b61ef7194a97b6873aef3ae5f26b7f275a2d5b4e07efad4b7b51a6f5ed7d1e76ffcf6 }

condition:
	$a0
}

        

rule Win_Trojan_Mybot_8319
{
strings:
	$a0 = { 71b4dedd54d3ee1ee839a27fbfaa8ad9fb5d00af8091ea84dc2f86f932e8d47f10f8c2483417b51ce8afe6dc5b68bf2f677ae5c51f8be71cd9b2ffa8d540d7560de162f94568071c9dd60ff05e471709d660f105ef91da09c32f050347bd2cc273326481 }

condition:
	$a0
}

        

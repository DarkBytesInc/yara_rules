rule Win_Trojan_Hupigon_983
{
strings:
	$a0 = { 1a2a9be02cd9556a731665d7757147eb7faf46e81772c4f3a0a8c8fa444e8fa528aa3583a07d9753058fa377adee8ed62d91e544eed8b90b47fcc76e4d9a2a61593425273b5cfd9257119dbf32bda750d094b18e04 }

condition:
	$a0
}

        

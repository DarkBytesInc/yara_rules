rule Html_Trojan_CoolEK_1
{
strings:
	$a0 = { 7472797b64736673642b2b7d636174636828774547574547574567297b }

condition:
	$a0
}

        

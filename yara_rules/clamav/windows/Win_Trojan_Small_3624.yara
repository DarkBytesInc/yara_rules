rule Win_Trojan_Small_3624
{
strings:
	$a0 = { 980c3f84d01f2ea400bf053497385ecafa687cf1410ff7031ec4c9813760e893be4e1f8139139a9f0f25d5f12a25f770f8199ff95c8bda21aa5c405c0e0ce10e8f60fdb8ec1cc4def61ac1dd92ef839067d6f7265e342db3f927 }

condition:
	$a0
}

        

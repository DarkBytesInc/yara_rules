rule Win_Trojan_Mybot_5522
{
strings:
	$a0 = { 0f80412c993a0b49a82bfe2928be26817df881f07f750939fd08618594d73c1288ffc875182a95b8f85d7fba12c8661adc27c1ec1798a4f96b13f7bde3c08a07548e335974ad }

condition:
	$a0
}

        

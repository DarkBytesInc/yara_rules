rule Win_Spyware_Banker_5701
{
strings:
	$a0 = { 41350995c0bc9535ddfa9310bfe8baf1e1ab6cbde3de440bc4ed2a6f8aba29554b3201e06f9a045fe819438f83622b521201f1a0b1534c3f84e404b3ae12eecf91db6b7dc2a54391b8c044d74f0e53abd54a59f554c36578c29d }

condition:
	$a0
}

        

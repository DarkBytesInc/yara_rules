rule Win_Spyware_ot_264
{
strings:
	$a0 = { a42b6845b350e14ce0ce63f2d1fab1b3df2dd8eb06f923c9e4bb3ea4d3cfa43509b1ba38310f5156ee5c9b0deda0306b1fd5f259036a679061483b31bdc42dc9875f85d1d98de8cbc8011103af985a4466a899441aa9de27 }

condition:
	$a0
}

        

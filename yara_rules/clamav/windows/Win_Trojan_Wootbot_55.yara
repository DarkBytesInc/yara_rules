rule Win_Trojan_Wootbot_55
{
strings:
	$a0 = { 7790ef2148a274bd16e7fc64d46e6c0f72c75004cd31cee1ebeb4ea45d14ab0375d62609eb195226582b2319a8c655d6dc6c795b5239637c3df54b8110c4c33863579311a3c8c155e02e46e1e93ab87fd7af415c212d1fd9c024d5b72c8b974d0022b8b3c2f3b77602effa0ab0db7d9830ec5fe1a6beb54fd8121e4b429a0a60f0e6794a199a7a568b09907bb8c0ad023938ab26e06a }

condition:
	$a0
}

        
rule Win_Trojan_Padodor_23
{
strings:
	$a0 = { 81f3773c000089d801d889c381ebe434000081eb3f7a000089d829d889c3f7e38985e0feffff89c381f31b6a000089d8f7e38985dcfeffff89c3f7e38985d8feffff89c38dbdecfeffff8d3590300010b904000000f3a5 }

condition:
	$a0
}

        

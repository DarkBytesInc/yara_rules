rule Win_Trojan_Skunk_2
{
strings:
	$a0 = { 77772e736b756e2e6261636b646f6f722e7072762e706c006f70656e00687474703a2f2f7777772e736b756e2e6261636b646f6f722e7072762e706c006f70656e006d61696c746f3a787472656d652d343340796f796f2e706c006f70656e }

condition:
	$a0
}

        
rule Win_Trojan_Rukap_84
{
strings:
	$a0 = { b26acfc48d78d22fdb0d91099645e95e5182ec58f1149ebab2f2e93378b430aa2547135672de6a6633445abb41a328578e100d21f643f79cc321338a57e8e431c63f17055d3835f230e9000584fb9d6177272a9d33b55a061d743c799ebf1b7f4180049f1918e7fb7f18f6d0a2d962c3bb885b6e1156602c613a867652c10460d747b62ee707634dd3 }

condition:
	$a0
}

        
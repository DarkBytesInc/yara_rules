rule Win_Trojan_SdBot_4276
{
strings:
	$a0 = { 1831df542893e6feeae4d5a328a87ce31742ae3c7c3b5b0c9df12efa9135dc7f81f71af0933b30188d7a0e54bf494976affdbd473c7f7c361fd1bd2a8791b05b4b85681f731a0493bbbfca4afa47fedc354e6ff6307f372b2029abd698fbf38cba9c2009ccdbb692a9dd7d75da0dbd4713177b7a4a80 }

condition:
	$a0
}

        

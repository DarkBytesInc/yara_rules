rule Html_Phishing_Pay_18
{
strings:
	$a0 = { 6163636f756e74206177616974696e672066757274686572206964656e7469747920766572696669636174696f6e2e3c62723e77652072657175697265207468617420796f7520766973697420746865206c696e6b2062656c6f7720616e642066696c6c206f7574 }

condition:
	$a0
}

        
rule Email_Phishing_Bank_1222
{
strings:
	$a0 = { 796f757220696e7465726e65742062616e6b696e6720686173206265656e200a0a626c6f636b656420666f7220796f75722073616665747920756e74696c20796f7520636f6e6669726d }

condition:
	$a0
}

        
rule Email_Phishing_Bank_1522
{
strings:
	$a0 = { 596f7572205465726d204465706f736974[0-15]686173206e6f77206265656e206f70656e656420616e6420697320617661696c61626c65[0-32]546f20766965772064657461696c73206f6620796f7572206e6577206163636f756e742c20676f20746f }

condition:
	$a0
}

        
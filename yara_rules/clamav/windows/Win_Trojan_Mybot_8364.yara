rule Win_Trojan_Mybot_8364
{
strings:
	$a0 = { 5e5e016bb6fed67e39e5a823791b747e9e97519c5696c7b46c691ec11998cbcb15226e93dcaa66ad0b3829d71fee669cc30d9d21793cdb9a9b4a21ce4a846be726fa140668e27b46aa80c576be4785ba7d7fb93580 }

condition:
	$a0
}

        

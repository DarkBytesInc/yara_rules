rule Html_Phishing_Bank_1182
{
strings:
	$a0 = { 62616e6b696e672070726f66696c6520686173206265656e206c6f636b65642064756520746f20696e6163746976697479206f722062656361757365206f6620746f6f206d616e79206661696c6564206c6f67696e20617474656d7074732e[0-20]706c6561736520636c69636b206e65787420746f20756e6c6f636b20796f757220696e7465726e65742062616e6b }

condition:
	$a0
}

        
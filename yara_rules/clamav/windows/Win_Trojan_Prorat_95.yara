rule Win_Trojan_Prorat_95
{
strings:
	$a0 = { 30256e926c175cbdeed2a8b9c9607f7a967eba0d17d73308b3dbfb497b2be1df99ff3dbe2abed7d14234e7270d8e47b2d3735f6a3bf193b0647f48440ea5926311f6ce4f9cfa9d61ca7aadbe2fa7429b24809c8ab86595c26815c057de7d2bf06fb1b1b1 }

condition:
	$a0
}

        

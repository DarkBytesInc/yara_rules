rule Win_Trojan_Agent_34914
{
strings:
	$a0 = { 6cf16912ca61e490cd0ef1c49bcdbabc4c21b3de856e89f4e961d89cdb93a8f8e517e4f8d52fae280c2b06fdb55ab0d4c95fac7c15351ca8d426f495942cb9809a67d3f4679ea97cd52e9fc629148a8e9d3bcafb0df57258ed21 }

condition:
	$a0
}

        

rule Win_Downloader_Banload_1246
{
strings:
	$a0 = { 31a820a323b11881438044e6f903841ccbd56dbf8b735deeb0fc3bf847bdd6bba816f73502eaf7bc072e640cb6bc837120b6af24169208d75016dd416e3a906d7506daea416dd4171cd482d3500b97501ebdd40b9deea03999a236f6ea2b9975975dffffff7bbfdf3e7dfbe73cf3ef9bfbe79bdf3f7f9eff022e688134c5fb5daed365b1da8890f9dff4e842 }

condition:
	$a0
}

        
rule Win_Downloader_Dadobra_236
{
strings:
	$a0 = { 0d0a8bb33f0e9f59d1e28f2d0b81a7edb4e75e2fbb8a4aeb0ecfcf7f8286213d893880cbd0e34f1ec010dce2ab38760fa64991eb3f14392a77cbaa6d95dbc7d9454299f3470e185ef0386e138942c26fb7758cc52dde71fc4352d190ea4826f57cb2db68e3388f8ed9caeee9 }

condition:
	$a0
}

        

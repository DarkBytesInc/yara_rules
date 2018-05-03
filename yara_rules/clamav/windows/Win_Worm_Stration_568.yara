rule Win_Worm_Stration_568
{
strings:
	$a0 = { 5b474743130000009ab6b7adbcb7adf495bcb7beadb1e3d9000000002f000000cbd7d7d3998c8ca3000000007c7e6f1b1e481b736f6f6b140a150a36317a58585e4b4f }

condition:
	$a0
}

        

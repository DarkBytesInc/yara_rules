rule Win_Downloader_1140_1
{
strings:
	$a0 = { 10dbceaeae2d91c2afa238cbc91e84b2f39bed2c1e4764645bdd7b9eafaf1ac856a0b66b9a1aa4d044ec2b37cded688b1d9144041f2cb212c0ca40d4e93762e7b29dd462a76b87de54c83602cbf1e4dc2c8b5cdc469a0d33709b1a7e }

condition:
	$a0
}

        

rule Win_Trojan_Prosiak_1
{
strings:
	$a0 = { 8c430812c2897a6c22061c44454c9c54acf4f2a45dd442e816e459a0ec58530e5452554392caa028f8242df2e3e7fc8150524f58599d4e41f9d324111cab21ce }

condition:
	$a0
}

        

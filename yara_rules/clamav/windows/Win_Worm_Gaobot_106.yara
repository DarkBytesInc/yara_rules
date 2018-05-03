rule Win_Worm_Gaobot_106
{
strings:
	$a0 = { 3a3a946d789e8adec2a7231dbb9623c6dde52f9ad34960e2f19b9aea29b05fbaf6f378a13e7b38824b0a5415b98791c63dd84c9dba0ffc9c785757b37d6337eda5433771f6178e79ea96c585b2abbf0e3f7afe90f2c8ac3b3fede64917586e2dbb93dc0cc1 }

condition:
	$a0
}

        

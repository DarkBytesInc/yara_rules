rule Win_Trojan_Spambot_112
{
strings:
	$a0 = { 008d58c592e397764f2f8fb3cd2dfffffffffb84b2dfdb85b92d41c601eba3f47d9f00922ff7b513f6da7a773286f7892a52ffa101fc6d5a2c3765c1abd1cf628fb1d0eb5ffcffe0e194b72b20e1a57f630e4664bbd79ee2fd1b0b71e0ffffffb69259f2feacd281c1524d1207b8 }

condition:
	$a0
}

        

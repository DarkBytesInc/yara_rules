rule Win_Trojan_Hupigon_1385
{
strings:
	$a0 = { 7900d1c8d82e9d28760fd445c1d046a9e9772101662b26aece165707881c0e7db792012aed48eb19e475c028c4e2fc702b2922ed83e66a5548de38b122e466372744316afe1fe2a2f47d1b82a2a6d5fdef07fbb76f7a58fe0a14809b6ebafc6bd51d7ebf74529c544b261e9c047c8b8267d52e391e60 }

condition:
	$a0
}

        
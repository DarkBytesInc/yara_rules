rule Win_Trojan_IRCBot_265
{
strings:
	$a0 = { ecc5e5aeef8f749ccffefcdf1cdf51a9a567d4696dcdcdbebdcf726d1fcbc471ff8c6160a72564ab9a65ddc50525cf89d2d07db6b8cf89d6bdc0a688ff556d5eccb5eeb92d69dfc5a5adefdbdceda7a4beff6d613cc4e52fcf796d38ba55eceff9614ec9b568ff556daecc2563df6d61bcc665a3ff87d43fcf15a3e8 }

condition:
	$a0
}

        

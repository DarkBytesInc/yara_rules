rule Win_Downloader_Small_4193
{
strings:
	$a0 = { 1027e5c95a380430ff359be0944539096828b410b16814b26764390bf00383c40c6a0533217101d31f773d68b773571cc858f03feb2c1b3db700f8c5730b741168ad0f7527367468c360ce423a04002d68a257ba7161f3c33f6a04dfc2d321b18c5a6a51011e50116d206515558becfc2232621801b265b76551e121165c4c1063458d0500d8467ad180385c }

condition:
	$a0
}

        
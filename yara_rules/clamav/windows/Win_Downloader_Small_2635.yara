rule Win_Downloader_Small_2635
{
strings:
	$a0 = { e2328e710b0b84724ce9080e7a6c9cc31ce85ff4a7b60df76aa12cc97c93633daf3b64437ec6b24da711b3741edec47ed60a5ccde2ac17ff1c1481672e3cbfbc2550a0e7410bfb7c5e3972e5def68974793af55d4058dc71e2711b110e5188fb44a5e217dffb956c511e378119110102da07ce0897ecf55982725de1 }

condition:
	$a0
}

        
rule Win_Downloader_Banload_1918
{
strings:
	$a0 = { 365f4fb69b759aff2d2b4d3af22b6ea254807cb07c3a2975a30c962ecd2fab03222a39f15a52f9e20d611a80b45609b37fc33e143fcdbdb3f6cd95408b44c88e40a8140c9db47640d07d129daa4265e85dce30544653b11b0d3333df803de55c6b30410b4823de91ac67c778d67291865d73493994c616cac135f96c2a222f508a727f6d }

condition:
	$a0
}

        
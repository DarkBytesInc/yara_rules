rule Win_Proxy_Lager_73
{
strings:
	$a0 = { aed324b8f0de0a13f6db747acad46c0d0909480672a9b17911f9fc3c17d6138f9daf9ce3e4b989782689028a474cc0ae16c1c4a81f4f8036f33ce633c117cf6739f9ffa20a8b }

condition:
	$a0
}

        

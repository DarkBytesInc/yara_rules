rule Win_Downloader_1113_1
{
strings:
	$a0 = { cebe6720a073d0c7cb1ae13044c449bfa1e9c24fe84388f87cd6bef65b53a3e88c886ff02ccabd4289e8343b4a0b2bb603f2ba1ae9a78749fe022d5c306c212af89ce080f00bd4eaa360825e5b21f3583dccbd9c404b808d930530b5 }

condition:
	$a0
}

        

rule Win_Trojan_Hupigon_826
{
strings:
	$a0 = { afbfb4c5071b7e5e89ba52ce81041d6ad6885394fc2b6fe889c9af264576fc4ed294c917804275cd23bf5c46888edd74882dd276da6b52450ffb6b790bcd32dd8fce44e21dc9989963aaf92d1849b087831ba9b4c951f2c6e59bf2d471c7e4 }

condition:
	$a0
}

        

rule Win_Trojan_Hupigon_715
{
strings:
	$a0 = { 5091fdadd3c2379e853ac044121c092228dcc73284e9f055dd09a2ad51bde187c7e595c563b1e91ed7c8e14155d273e69f2b7373c16d2e24c09bbfbd1e3c9011f8deedb06dfbc7ae7b801b829a91e821e74ce4d41f96153a }

condition:
	$a0
}

        

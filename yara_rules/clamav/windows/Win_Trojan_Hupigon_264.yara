rule Win_Trojan_Hupigon_264
{
strings:
	$a0 = { 14018a29ba800afd3adeeed73887d9ed5a9f08c31a36b7ddf8bbea9ae115786e903828e4154ca73f8db1da161ffa3a0b7a68407c368cd773a3f1767b9a6e04b5429303d69f7d08910fd0bc80a9ce7b22a2a91f6ed9a76284b73a }

condition:
	$a0
}

        

rule Win_Spyware_Banker_2396
{
strings:
	$a0 = { b5aef1b8a50579d6b71a809912947ef07c09365f5d6a4fa40bbf023eae0caf27f6c56057ff9678d870895f997bbafe90d719db65455d0e3af7152bb33f5b32f7344d0eb8627a7245b96ad47aaa60d7d52278ad8fb8e67ceae6c48a71fa0aeebf5a68051bb84ab05fa7aed6b05cd8770bf49f }

condition:
	$a0
}

        

rule Win_Trojan_Small_3853
{
strings:
	$a0 = { b7e5fdfe10075d4b3e9d547bf76a09757a5681aa7c46fd7aef6a0d58a75f3df0d12ea1ef7a4657743ba00c751c48fdef7a7c5109bb4654d8d580fdefd4cbbd49ef5ffc25b35f3df0d12e462a7b4656753ba072f7e547e6637c }

condition:
	$a0
}

        

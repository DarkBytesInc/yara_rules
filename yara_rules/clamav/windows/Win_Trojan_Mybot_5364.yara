rule Win_Trojan_Mybot_5364
{
strings:
	$a0 = { 29eb44d093e63f20bd68eb37f0917edf301ffb17e46aa6a9e6646978a8345d76ee706fed0badf809aad15a6f2cfb273ba184418400781502b83a699d6446949e26c9141342654d99163b2d74f8d85ab94c2940a397955c95a7e51ee02044d94cb9a14452fe3eacc88bb41e6ed0c9344ac949ac473039f2611a93c62fd043c6c940ce5276966d3edcd9ed7f981764dff7565c5dbf8014 }

condition:
	$a0
}

        
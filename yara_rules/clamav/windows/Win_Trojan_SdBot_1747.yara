rule Win_Trojan_SdBot_1747
{
strings:
	$a0 = { 50071020e6034f2ff9be258cbebc95b10c926d72694277a90164a165d205e2e4c9c59ed212f3f6b3841e027c1c40194c3cdb318a92d464da6e725dce7d30469a7bd01b90352cd298f14079e825e7a4a4d9850dd02e2accf5b03353c221af7b6398fc4d3d2f5f6955f695d96e05e123021f4082da0b794c517bed4775 }

condition:
	$a0
}

        
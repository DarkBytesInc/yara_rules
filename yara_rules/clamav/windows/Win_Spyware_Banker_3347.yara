rule Win_Spyware_Banker_3347
{
strings:
	$a0 = { 0ba2b062046c43ca33b6a8ef091d9ed0517264f64944c0578abfc150dc5da2e33bbe7961dbb972a8b03af252a595d7cab22fbcb1f549c22784acbd7a3d1b349a45e097718723c17b1e76a6beba5fbd16bb3b079f3588823c12329860fe615b8c6db65d }

condition:
	$a0
}

        
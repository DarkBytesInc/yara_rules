rule Win_Spyware_Banker_4013
{
strings:
	$a0 = { 080828fb1f4461d2843a26b5a81081798bb1bcdfe16ef9ce657f40bccce6016ef7902ddddc06ddd21c6aea2bb583bb56415a482bb7920adc05b6e41ddae416f1cd41b6e406b72406b9016dc80e3701ddbcc91b72e03bdf1c8af37bc6ef7fffffef73fbe7cfbf7ceff7cf7cd66bf6f9dfe0460d102692b362b1586bf5eddc890f9bff7c2028b95eb0b3d7c2aa }

condition:
	$a0
}

        
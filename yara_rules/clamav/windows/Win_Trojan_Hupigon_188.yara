rule Win_Trojan_Hupigon_188
{
strings:
	$a0 = { 36af0617fd76a99133eaf3f1e3c4d1b1fa672820010c003edeae1f02f01d2b0cd0f536f84a80fda6174a59f900df0846d3f44a962367fe181e6bff9ddbe501395d29c5898c4cb8a9e1cd5de339fac57b62694cb7db0fb523006c8cc3a16bb54bb55f5bb3bce48e01f6 }

condition:
	$a0
}

        

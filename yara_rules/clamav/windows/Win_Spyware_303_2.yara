rule Win_Spyware_303_2
{
strings:
	$a0 = { efd0e28f1497abfe170b1c6e01a27e1acfe0fbba9d9226b5b191a7fa267e1d4fe8198279269df3e6d6c66fd19ea4b6565788416db7bd60656a13c65e713da06c6a378dd8857afbcc6adc2daa0407d45666dbfc20de3c9ec2f1ec6d016b8864 }

condition:
	$a0
}

        

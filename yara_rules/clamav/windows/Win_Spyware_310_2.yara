rule Win_Spyware_310_2
{
strings:
	$a0 = { 69f2b3d7670a97cba820adc3724feb7bbcf07c1123befbd9cf6abfa74542de1f967a3a7985fab01e41521e6cec8ff7db9e39bd9fb716bd20bc5407676a6c947645b3a05958f2bc370ec180c1ba2d4c2baf59f9352bd2d771e92824b67f078f }

condition:
	$a0
}

        

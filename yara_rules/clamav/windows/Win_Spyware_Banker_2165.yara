rule Win_Spyware_Banker_2165
{
strings:
	$a0 = { 39e973666acb668bbb0c874ee989eca4b8a46193e5c42fedd78d080da9132b6525b5cc0b915593fbaad7f80360e144b0f929a66c6f3d251127f3939108a23ce5f22ecfa03a43bd96b580db6c0003 }

condition:
	$a0
}

        

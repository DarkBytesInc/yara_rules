rule Win_Worm_Mytob_415
{
strings:
	$a0 = { 7772e37df86f1c405c8e628d2ef13596d34602e8db77f1bb1fd9e6fe9318b0b9617e3e693a318437919b5946461132b54e922453c902a55b1be7c96eebe0e1b56c5ed63651408a7c59b2c17ecf074951306777b1b0cc2bdad5ca5bdb50de9d1cf38e0a9d7e930cae97cc350c581329b8640e21847f02dec963efab26c7359c997d442f3886137570c627a60e97e2a8b31bdeaedd44de }

condition:
	$a0
}

        
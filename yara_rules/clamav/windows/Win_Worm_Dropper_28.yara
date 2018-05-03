rule Win_Worm_Dropper_28
{
strings:
	$a0 = { 888eca65eee9cc58dfbac4da6fbd21c9ae21136fa374e6bb41bb56898f48c4a493cbf773056ac52d47fefa65a0384c22f1ddeccfafac976debed7f5e74233460b29bb3da2ee398a4a001b8867b69553415ca770302b95269dae9ac22de7b992dd8a5abca7fa4e29c76d3ffa1a83f9735d2d173402332545b776e3a }

condition:
	$a0
}

        

rule Win_Spyware_496_2
{
strings:
	$a0 = { fdad9df6fce7de58fcad8a9330526223c327db59b6ee9c59fcba789503523d6fc007e94a809692f05438674ef1929d596b8c0cb2103a6df314418a25c7ad9dadc326674e49ad9d596b9e0cb2103a6df314418acdc7ad9dadc326 }

condition:
	$a0
}

        

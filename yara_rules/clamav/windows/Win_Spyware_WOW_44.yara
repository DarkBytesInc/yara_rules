rule Win_Spyware_WOW_44
{
strings:
	$a0 = { 5baa7c0e80270a3b8f75b795318d5b1d601e9ad6bdc31756a6953df317a17597d2b1cca38e13efae03a476b8c86effbacb5cab417c9ca45282b7e5877900217f3d08aeb91672ceab9ce03a6f7416432c008cbb6ed8c217ed53e547ed01441d7b0e1c }

condition:
	$a0
}

        

rule Win_Spyware_Banker_1567
{
strings:
	$a0 = { d6f8379eac531b11612561a7e71c1dcf5f0a4daefa087180e3fecea3732c0dc5d07610fb35eaacd446aecb0b60a1a17823f7ad977fcc73b770c1c6ffda8011967ef07bbcd0a176a4f67f7a8c3bda4ec23f77175c0b2b9c111d54065924bf58df927159d152a7155fc26ccdfa677e1df57e9c1c2d8abd5867 }

condition:
	$a0
}

        

rule Win_Dropper_Agent_33891
{
strings:
	$a0 = { 82742bbd7ea1435d3d72428c065d88c58717c114609c7b42ec351ae1a6c4325441544e6c9895b36dd9d3555a940f5d020bcea2ee970c24ffecff3e5080215250ba4d6926fe5cef1f6dc816fc54f9439f3499a6fb1ad179637b296d4400679c5483d21e91bb65655562c53718168a697c3b0cd9ff87b3877ba4b4fa3944dc8ca6aeb2f9dc47715b86264bd3 }

condition:
	$a0
}

        
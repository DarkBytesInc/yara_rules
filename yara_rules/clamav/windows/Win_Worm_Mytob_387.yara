rule Win_Worm_Mytob_387
{
strings:
	$a0 = { 4252412a4bc71884544f4d494756c621b342dcc523b342431b459ed37a762434236a7875cf21a2d63b3a3937522a2a31ab332130b2aba1212425792702520414038954e0859a1870e615164808136d1503129845fb9548fc8bc60c640af9fa7886ea71950afe3bb90fe7797512e090f8d022b1b0bf9648ecebeae63f575b20d5a6c927554fd3d2d3daaec223d5304054cecdcec1bbd7 }

condition:
	$a0
}

        
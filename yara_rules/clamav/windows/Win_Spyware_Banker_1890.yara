rule Win_Spyware_Banker_1890
{
strings:
	$a0 = { 40d0c8c03055471d545b86505ec6cbe4c1edd56576f7adcf4a4f2228021ce32c8034ea34bda9142178e92e2787796b98da47f4dc8770520d984e753457df732ba1abd4534d4678f1a5ddbe17a0feeb3148de8b5d62edade4289bf72cb80db7fe042e252c13b95483c1794ba16462ddeb30d4d27af53b29bc1c0f35ccb44d944b628f93a1b73e02100bff7c6c53699ce422a1e5f5 }

condition:
	$a0
}

        